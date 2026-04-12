import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import click
from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError

from cleancloud.core.finding import Finding
from cleancloud.output.progress import advance
from cleancloud.providers.azure.rules.aml_compute_idle import find_idle_aml_compute
from cleancloud.providers.azure.rules.aml_compute_instance_idle import (
    find_idle_aml_compute_instances,
)
from cleancloud.providers.azure.rules.app_gateway_no_backends import (
    find_app_gateway_no_backends,
)
from cleancloud.providers.azure.rules.app_service_idle import find_idle_app_services
from cleancloud.providers.azure.rules.app_service_plan_empty import (
    find_empty_app_service_plans,
)
from cleancloud.providers.azure.rules.container_registry_unused import (
    find_unused_container_registries,
)
from cleancloud.providers.azure.rules.disk_snapshots_old import find_old_snapshots
from cleancloud.providers.azure.rules.lb_no_backends import find_lb_no_backends
from cleancloud.providers.azure.rules.openai_provisioned_idle import (
    find_idle_openai_provisioned_deployments,
)
from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips
from cleancloud.providers.azure.rules.sql_database_idle import find_idle_sql_databases
from cleancloud.providers.azure.rules.unattached_managed_disks import (
    find_unattached_managed_disks,
)
from cleancloud.providers.azure.rules.untagged_resources import (
    find_untagged_resources as find_azure_untagged_resources,
)
from cleancloud.providers.azure.rules.vm_stopped_not_deallocated import (
    find_stopped_not_deallocated_vms,
)
from cleancloud.providers.azure.rules.vnet_gateway_idle import find_idle_vnet_gateways
from cleancloud.providers.azure.session import create_azure_session
from cleancloud.providers.azure.validate import (
    validate_region_params,
    validate_subscription_params,
)


@dataclass
class SubscriptionScanResult:
    subscription_id: str
    subscription_name: str
    status: str  # "success" | "failed"
    findings: List[Finding] = field(default_factory=list)
    skipped_rules: List[dict] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def estimated_monthly_cost(self) -> float:
        return sum(
            f.estimated_monthly_cost_usd
            for f in self.findings
            if f.estimated_monthly_cost_usd is not None
        )


AZURE_RULE_MAP: Dict[str, Callable] = {
    "azure.compute.disk.unattached": find_unattached_managed_disks,
    "azure.compute.snapshot.old": find_old_snapshots,
    "azure.resource.untagged": find_azure_untagged_resources,
    "azure.network.public_ip.unused": find_unused_public_ips,
    "azure.app_service_plan.empty": find_empty_app_service_plans,
    "azure.load_balancer.no_backends": find_lb_no_backends,
    "azure.application_gateway.no_backends": find_app_gateway_no_backends,
    "azure.virtual_network_gateway.idle": find_idle_vnet_gateways,
    "azure.vm.stopped_not_deallocated": find_stopped_not_deallocated_vms,
    "azure.sql.database.idle": find_idle_sql_databases,
    "azure.app_service.idle": find_idle_app_services,
    "azure.container_registry.unused": find_unused_container_registries,
}

AZURE_RULE_MAP_AI: Dict[str, Callable] = {
    "azure.aml.compute.idle": find_idle_aml_compute,
    "azure.ml.compute_instance.idle": find_idle_aml_compute_instances,
    "azure.openai.provisioned_deployment.idle": find_idle_openai_provisioned_deployments,
}

AZURE_RULES: List[Callable] = list(AZURE_RULE_MAP.values())

# AI/ML waste rules — not run by default; use --category ai or --category all
AZURE_AI_RULES: List[Callable] = list(AZURE_RULE_MAP_AI.values())

_TRANSIENT_STATUS_CODES = {429, 500, 503}
_MAX_RETRIES = 3


def _parse_retry_after(e: HttpResponseError) -> Optional[int]:
    try:
        header = e.response.headers.get("Retry-After")
        return int(header) if header else None
    except Exception:
        return None


def _run_rule_with_retry(
    rule: Callable,
    subscription_id: str,
    credential,
    region_filter: Optional[str],
) -> List[Finding]:
    for attempt in range(_MAX_RETRIES):
        try:
            result = rule(
                subscription_id=subscription_id,
                credential=credential,
                region_filter=region_filter,
            )
            return result if result is not None else []
        except HttpResponseError as e:
            if e.status_code in _TRANSIENT_STATUS_CODES and attempt < _MAX_RETRIES - 1:
                wait = _parse_retry_after(e) or (2**attempt)
                click.echo(
                    f"  Retrying {rule.__name__} (attempt {attempt + 2}/{_MAX_RETRIES}, wait {wait}s) ..."
                )
                time.sleep(min(wait, 60))
            else:
                raise


def scan_azure_with_region_selection(
    region: Optional[str],
    subscriptions: Optional[List[str]] = None,
    all_subscriptions: bool = False,
    management_group: Optional[str] = None,
    rules: Optional[List[Callable]] = None,
) -> Tuple[str, List[Finding], List[str], List[dict], List[SubscriptionScanResult]]:
    # Validate subscription parameters
    validate_subscription_params(subscriptions, all_subscriptions)

    # Validate region parameter
    validate_region_params(region)

    click.echo("Authenticating to Azure")
    click.echo()

    session = create_azure_session()

    # Management Group auto-discovery
    if management_group:
        click.echo(f"Discovering subscriptions in management group: {management_group}")
        all_accessible = session.list_subscriptions_in_management_group(management_group)
        subscription_selection_mode = "management-group"
    else:
        all_accessible = session.list_subscriptions()
        subscription_selection_mode = "all"

    if not all_accessible:
        raise PermissionError("No accessible Azure subscriptions found")

    # Build id -> name map for tagging findings
    sub_name_map: Dict[str, str] = {s["id"]: s["name"] for s in all_accessible}
    accessible_ids = set(sub_name_map.keys())

    # Determine which subscriptions to scan
    if subscriptions:
        subscription_selection_mode = "explicit"
        inaccessible = set(subscriptions) - accessible_ids
        if inaccessible:
            click.echo(f"Warning: {len(inaccessible)} subscription(s) not accessible:")
            for sub_id in sorted(inaccessible)[:5]:
                click.echo(f"   - {sub_id}")
            if len(inaccessible) > 5:
                click.echo(f"   ... and {len(inaccessible) - 5} more")
            click.echo()

        subscription_ids = [s for s in subscriptions if s in accessible_ids]
        if not subscription_ids:
            raise PermissionError("None of the specified subscriptions are accessible")

        # Add names for explicitly requested subs not in the accessible list
        for sub_id in subscription_ids:
            sub_name_map.setdefault(sub_id, sub_id)

        click.echo(f"Scanning {len(subscription_ids)} specified subscription(s)")
    else:
        subscription_ids = list(accessible_ids)
        click.echo(f"Found {len(subscription_ids)} accessible subscription(s)")

    click.echo()

    sub_results = scan_azure_subscriptions(
        subscription_ids,
        sub_name_map,
        session.credential,
        region,
        rules=rules,
    )

    click.echo()

    all_findings = [f for r in sub_results for f in r.findings]
    skipped_rules: List[dict] = [skipped for r in sub_results for skipped in r.skipped_rules]

    subscriptions_scanned = [r.subscription_id for r in sub_results if r.status == "success"]

    return (
        subscription_selection_mode,
        all_findings,
        subscriptions_scanned,
        skipped_rules,
        sub_results,
    )


def scan_azure_subscriptions(
    subscription_ids: List[str],
    sub_name_map: Dict[str, str],
    credential,
    region_filter: Optional[str],
    rules: Optional[List[Callable]] = None,
) -> List[SubscriptionScanResult]:
    results: List[SubscriptionScanResult] = []

    for sub_id in subscription_ids:
        click.echo(f"  {sub_name_map.get(sub_id, sub_id)}")

    with click.progressbar(
        length=len(subscription_ids),
        label="Scanning Azure subscriptions",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(subscription_ids))) as executor:
            futures = {
                executor.submit(
                    _scan_azure_subscription,
                    subscription_id=sub_id,
                    subscription_name=sub_name_map.get(sub_id, sub_id),
                    credential=credential,
                    region_filter=region_filter,
                    rules=rules,
                ): sub_id
                for sub_id in subscription_ids
            }

            for future in as_completed(futures):
                sub_id = futures[future]
                sub_name = sub_name_map.get(sub_id, sub_id)
                try:
                    sub_findings, sub_skipped = future.result()
                    results.append(
                        SubscriptionScanResult(
                            subscription_id=sub_id,
                            subscription_name=sub_name,
                            status="success",
                            findings=sub_findings,
                            skipped_rules=sub_skipped,
                        )
                    )
                except Exception as e:
                    click.echo(f"  Subscription {sub_name} ({sub_id}) failed: {e}")
                    results.append(
                        SubscriptionScanResult(
                            subscription_id=sub_id,
                            subscription_name=sub_name,
                            status="failed",
                            error=str(e),
                        )
                    )
                finally:
                    advance(bar)

    results.sort(key=lambda r: r.subscription_name)
    return results


def _scan_azure_subscription(
    subscription_id: str,
    subscription_name: str,
    credential,
    region_filter: Optional[str],
    rules: Optional[List[Callable]] = None,
) -> Tuple[List[Finding], List[dict]]:
    findings: List[Finding] = []
    skipped_rules: List[dict] = []
    rules_succeeded = 0
    rules_failed = 0
    resource_not_found_errors = 0

    rules_to_run = rules if rules is not None else AZURE_RULES

    with ThreadPoolExecutor(max_workers=min(2, len(rules_to_run))) as executor:
        futures = {
            executor.submit(
                _run_rule_with_retry,
                rule,
                subscription_id,
                credential,
                region_filter,
            ): rule
            for rule in rules_to_run
        }

        for future in as_completed(futures):
            rule = futures[future]
            try:
                rule_findings = future.result(timeout=120)
                # Tag each finding with subscription identity
                for f in rule_findings:
                    f.account_id = subscription_id
                    f.account_name = subscription_name
                findings.extend(rule_findings)
                rules_succeeded += 1
            except PermissionError as e:
                skipped_rules.append(
                    {
                        "rule": rule.__name__,
                        "missing_permissions": str(e),
                        "subscription_id": subscription_id,
                        "subscription_name": subscription_name,
                    }
                )
            except EnvironmentError:
                # Azure auth failed mid-scan — re-raise immediately
                raise
            except HttpResponseError as e:
                if e.status_code == 403:
                    skipped_rules.append(
                        {
                            "rule": rule.__name__,
                            "missing_permissions": "Azure Reader role permission denied (403)",
                            "subscription_id": subscription_id,
                            "subscription_name": subscription_name,
                        }
                    )
                else:
                    rules_failed += 1
                    click.echo(
                        f"  Rule failed: {rule.__name__} ({subscription_name}) — {type(e).__name__} {e.status_code}"
                    )
            except ResourceNotFoundError:
                rules_failed += 1
                resource_not_found_errors += 1
                click.echo(
                    f"  Rule failed: {rule.__name__} ({subscription_name}) — ResourceNotFound"
                )
            except (AzureError, Exception) as e:
                rules_failed += 1
                click.echo(
                    f"  Rule failed: {rule.__name__} ({subscription_name}) — {type(e).__name__}"
                )

    if rules_succeeded == 0 and not skipped_rules and resource_not_found_errors == rules_failed:
        raise RuntimeError(
            f"Subscription '{subscription_id}' appears invalid or inaccessible. "
            f"All {rules_failed} rules failed with 'ResourceNotFound' errors."
        )

    if rules_succeeded == 0 and not skipped_rules and rules_failed > 0:
        raise RuntimeError(
            f"All {rules_failed} rules failed in subscription '{subscription_id}'. "
            f"This indicates a serious configuration or permissions issue."
        )

    return findings, skipped_rules
