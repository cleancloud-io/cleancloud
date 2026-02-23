from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

import click
from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError

from cleancloud.core.finding import Finding
from cleancloud.output.progress import advance
from cleancloud.providers.azure.rules.app_gateway_no_backends import (
    find_app_gateway_no_backends,
)
from cleancloud.providers.azure.rules.app_service_plan_empty import (
    find_empty_app_service_plans,
)
from cleancloud.providers.azure.rules.ebs_snapshots_old import find_old_snapshots
from cleancloud.providers.azure.rules.lb_no_backends import find_lb_no_backends
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


def scan_azure_with_region_selection(
    region: Optional[str],
    subscriptions: Optional[List[str]] = None,
    all_subscriptions: bool = False,
) -> Tuple[str, List[Finding], List[str]]:
    # Validate subscription parameters
    validate_subscription_params(subscriptions, all_subscriptions)

    # Validate region parameter
    validate_region_params(region)

    click.echo("Authenticating to Azure")
    click.echo()

    session = create_azure_session()
    all_accessible_subscriptions = session.list_subscription_ids()

    if not all_accessible_subscriptions:
        raise PermissionError("No accessible Azure subscriptions found")

    # Determine which subscriptions to scan
    if subscriptions:
        # Specific subscription(s) requested
        subscription_ids = subscriptions
        subscription_selection_mode = "explicit"

        # Validate that requested subscriptions are accessible
        inaccessible = set(subscription_ids) - set(all_accessible_subscriptions)
        if inaccessible:
            click.echo(f"Warning: {len(inaccessible)} subscription(s) not accessible:")
            for sub_id in sorted(inaccessible)[:5]:
                click.echo(f"   - {sub_id}")
            if len(inaccessible) > 5:
                click.echo(f"   ... and {len(inaccessible) - 5} more")
            click.echo()

            # Only scan accessible ones
            subscription_ids = [s for s in subscription_ids if s in all_accessible_subscriptions]

            if not subscription_ids:
                raise PermissionError("None of the specified subscriptions are accessible")

        click.echo(f"Scanning {len(subscription_ids)} specified subscription(s)")
    else:
        # Default: scan all accessible subscriptions
        subscription_ids = all_accessible_subscriptions
        subscription_selection_mode = "all"
        click.echo(f"Found {len(subscription_ids)} accessible subscription(s)")

    click.echo()

    findings, skipped_rules = scan_azure_subscriptions(
        subscription_ids,
        session.credential,
        region,
    )

    click.echo()

    # Return subscription info (not region info)
    subscriptions_scanned = subscription_ids

    return subscription_selection_mode, findings, subscriptions_scanned, skipped_rules


AZURE_RULES: List[Callable] = [
    find_unattached_managed_disks,
    find_old_snapshots,
    find_azure_untagged_resources,
    find_unused_public_ips,
    find_empty_app_service_plans,
    find_lb_no_backends,
    find_app_gateway_no_backends,
    find_idle_vnet_gateways,
    find_stopped_not_deallocated_vms,
    find_idle_sql_databases,
]


def scan_azure_subscriptions(
    subscription_ids: List[str],
    credential,
    region_filter: Optional[str],
) -> Tuple[List[Finding], List[dict]]:
    all_findings: List[Finding] = []
    all_skipped_rules: List[dict] = []

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
                    credential=credential,
                    region_filter=region_filter,
                ): sub_id
                for sub_id in subscription_ids
            }

            for future in as_completed(futures):
                sub_id = futures[future]
                try:
                    sub_findings, sub_skipped = future.result()
                    all_findings.extend(sub_findings)
                    # Deduplicate skipped rules across subscriptions
                    for skipped in sub_skipped:
                        if not any(s["rule"] == skipped["rule"] for s in all_skipped_rules):
                            all_skipped_rules.append(skipped)
                except RuntimeError as e:
                    # RuntimeError indicates a complete subscription failure (all rules failed)
                    # This is fatal for explicitly requested subscriptions
                    click.echo(f"Subscription {sub_id} failed: {e}")
                    advance(bar)
                    raise  # Re-raise to fail the entire scan
                except Exception as e:
                    # Other exceptions might be transient - log and continue
                    click.echo(f"Subscription {sub_id} failed: {e}")
                    advance(bar)

    return all_findings, all_skipped_rules


def _scan_azure_subscription(
    subscription_id: str,
    credential,
    region_filter: Optional[str],
) -> Tuple[List[Finding], List[dict]]:
    findings: List[Finding] = []
    skipped_rules: List[dict] = []
    rules_succeeded = 0
    rules_failed = 0
    resource_not_found_errors = 0

    with click.progressbar(
        length=len(AZURE_RULES),
        label=f"Scanning Azure rules in subscription {subscription_id}",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(AZURE_RULES))) as executor:
            futures = {
                executor.submit(
                    rule,
                    subscription_id=subscription_id,
                    credential=credential,
                    region_filter=region_filter,
                ): rule
                for rule in AZURE_RULES
            }

            for future in as_completed(futures):
                rule = futures[future]
                try:
                    rule_findings = future.result()
                    findings.extend(rule_findings)
                    rules_succeeded += 1
                except PermissionError as e:
                    # Graceful degradation — missing permissions skip this rule
                    skipped_rules.append({"rule": rule.__name__, "missing_permissions": str(e)})
                except HttpResponseError as e:
                    if e.status_code == 403:
                        # Treat 403 as a skipped rule (missing Azure RBAC permission)
                        skipped_rules.append(
                            {
                                "rule": rule.__name__,
                                "missing_permissions": "Azure Reader role permission denied (403)",
                            }
                        )
                    else:
                        rules_failed += 1
                        click.echo(f"Azure rule failed in subscription {subscription_id}: {e}")
                except ResourceNotFoundError as e:
                    # Resource not found - likely invalid subscription ID
                    rules_failed += 1
                    resource_not_found_errors += 1
                    click.echo(f"Azure rule failed in subscription {subscription_id}: {e}")
                except AzureError as e:
                    # Other Azure SDK errors
                    rules_failed += 1
                    click.echo(f"Azure rule failed in subscription {subscription_id}: {e}")
                except Exception as e:
                    # Unexpected errors
                    rules_failed += 1
                    click.echo(f"Azure rule failed in subscription {subscription_id}: {e}")
                finally:
                    advance(bar)

    # If ALL rules failed due to resource not found (none skipped), subscription is likely invalid
    if rules_succeeded == 0 and not skipped_rules and resource_not_found_errors == rules_failed:
        raise RuntimeError(
            f"Subscription '{subscription_id}' appears to be invalid or inaccessible. "
            f"All {rules_failed} rules failed with 'ResourceNotFound' errors. "
            f"Check that the subscription ID is correct and accessible."
        )

    # If ALL rules failed for any non-permission reason, something is seriously wrong
    if rules_succeeded == 0 and not skipped_rules and rules_failed > 0:
        raise RuntimeError(
            f"All {rules_failed} rules failed in subscription '{subscription_id}'. "
            f"This indicates a serious configuration or permissions issue."
        )

    return findings, skipped_rules
