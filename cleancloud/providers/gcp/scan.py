import random
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import click
from google.api_core.exceptions import (
    GoogleAPICallError,
    PermissionDenied,
    ResourceExhausted,
    ServiceUnavailable,
)

from cleancloud.core.finding import Finding
from cleancloud.output.progress import advance
from cleancloud.providers.gcp.rules.disk_unattached import find_unattached_disks
from cleancloud.providers.gcp.rules.ip_unused import find_unused_static_ips
from cleancloud.providers.gcp.rules.snapshot_old import find_old_snapshots
from cleancloud.providers.gcp.rules.sql_instance_idle import find_idle_sql_instances
from cleancloud.providers.gcp.rules.vertex_endpoint_idle import find_idle_vertex_endpoints
from cleancloud.providers.gcp.rules.vm_stopped import find_stopped_vms
from cleancloud.providers.gcp.rules.workbench_idle import find_idle_workbench_instances
from cleancloud.providers.gcp.session import create_gcp_session
from cleancloud.providers.gcp.validate import validate_project_params, validate_region_params

_MAX_RETRIES = 3
_MAX_GLOBAL_WORKERS = 16


@dataclass
class ProjectScanResult:
    project_id: str
    project_name: str
    status: str  # "success" | "failed"
    findings: List[Finding] = field(default_factory=list)
    skipped_rules: List[dict] = field(default_factory=list)
    rules_succeeded: int = 0
    rules_failed: int = 0
    error: Optional[str] = None

    @property
    def rules_skipped(self) -> int:
        return len(self.skipped_rules)

    @property
    def estimated_monthly_cost(self) -> float:
        return round(
            sum(
                f.estimated_monthly_cost_usd
                for f in self.findings
                if f.estimated_monthly_cost_usd is not None
            ),
            2,
        )


GCP_RULE_MAP: Dict[str, Callable] = {
    "gcp.compute.disk.unattached": find_unattached_disks,
    "gcp.compute.vm.stopped": find_stopped_vms,
    "gcp.compute.ip.unused": find_unused_static_ips,
    "gcp.compute.snapshot.old": find_old_snapshots,
    "gcp.sql.instance.idle": find_idle_sql_instances,
}

GCP_RULE_MAP_AI: Dict[str, Callable] = {
    "gcp.vertex.endpoint.idle": find_idle_vertex_endpoints,
    "gcp.vertex.workbench.idle": find_idle_workbench_instances,
}

GCP_RULES: List[Callable] = list(GCP_RULE_MAP.values())

# AI/ML waste rules — not run by default; use --category ai or --category all
GCP_AI_RULES: List[Callable] = list(GCP_RULE_MAP_AI.values())


def _run_rule_with_retry(
    rule: Callable,
    project_id: str,
    credentials,
    region_filter: Optional[str],
) -> List[Finding]:
    for attempt in range(_MAX_RETRIES):
        try:
            result = rule(
                project_id=project_id,
                credentials=credentials,
                region_filter=region_filter,
            )
            return result if result is not None else []
        except (ServiceUnavailable, ResourceExhausted):
            if attempt < _MAX_RETRIES - 1:
                wait = (2**attempt) + random.uniform(0, 1)
                click.echo(
                    f"  Retrying {rule.__name__} "
                    f"(attempt {attempt + 2}/{_MAX_RETRIES}, wait {wait}s) ..."
                )
                time.sleep(min(wait, 60))
            else:
                raise


def scan_gcp_with_project_selection(
    region: Optional[str],
    projects: Optional[List[str]] = None,
    all_projects: bool = False,
    concurrency: int = 4,
    rules: Optional[List[Callable]] = None,
) -> Tuple[str, List[Finding], List[str], List[dict], List[ProjectScanResult]]:
    validate_project_params(projects, all_projects)
    validate_region_params(region)

    click.echo("Authenticating to GCP")
    click.echo()

    session = create_gcp_session()

    all_accessible = session.list_projects()

    if not all_accessible:
        raise PermissionError("No accessible GCP projects found")

    project_name_map: Dict[str, str] = {p["id"]: p["name"] for p in all_accessible}
    accessible_ids = set(project_name_map.keys())

    if projects:
        project_selection_mode = "explicit"
        inaccessible = set(projects) - accessible_ids
        if inaccessible:
            click.echo(f"Warning: {len(inaccessible)} project(s) not accessible:")
            for proj_id in sorted(inaccessible)[:5]:
                click.echo(f"   - {proj_id}")
            if len(inaccessible) > 5:
                click.echo(f"   ... and {len(inaccessible) - 5} more")
            click.echo()

        project_ids = [p for p in projects if p in accessible_ids]
        if not project_ids:
            raise PermissionError("None of the specified projects are accessible")

        for proj_id in project_ids:
            project_name_map.setdefault(proj_id, proj_id)

        click.echo(f"Scanning {len(project_ids)} specified project(s)")
    else:
        project_ids = list(accessible_ids)
        project_selection_mode = "all"
        click.echo(f"Found {len(project_ids)} accessible project(s)")

    click.echo()

    project_results = scan_gcp_projects(
        project_ids,
        project_name_map,
        session.credentials,
        region,
        concurrency=concurrency,
        rules=rules,
    )

    click.echo()

    all_findings = [f for r in project_results for f in r.findings]
    skipped_rules: List[dict] = [skipped for r in project_results for skipped in r.skipped_rules]
    projects_scanned = [r.project_id for r in project_results if r.status == "success"]

    return (
        project_selection_mode,
        all_findings,
        projects_scanned,
        skipped_rules,
        project_results,
    )


def scan_gcp_projects(
    project_ids: List[str],
    project_name_map: Dict[str, str],
    credentials,
    region_filter: Optional[str],
    concurrency: int = 4,
    rules: Optional[List[Callable]] = None,
) -> List[ProjectScanResult]:
    if not project_ids:
        return []
    rules_to_run = rules if rules is not None else GCP_RULES
    results: List[ProjectScanResult] = []
    max_workers = min(concurrency, len(project_ids), _MAX_GLOBAL_WORKERS)

    with click.progressbar(
        length=len(project_ids),
        label="Scanning GCP projects",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _scan_gcp_project,
                    project_id=proj_id,
                    project_name=project_name_map.get(proj_id, proj_id),
                    credentials=credentials,
                    region_filter=region_filter,
                    rules=rules_to_run,
                ): proj_id
                for proj_id in project_ids
            }

            for future in as_completed(futures):
                proj_id = futures[future]
                proj_name = project_name_map.get(proj_id, proj_id)
                try:
                    proj_findings, proj_skipped, rules_succeeded, rules_failed = future.result()
                    results.append(
                        ProjectScanResult(
                            project_id=proj_id,
                            project_name=proj_name,
                            status="success",
                            findings=proj_findings,
                            skipped_rules=proj_skipped,
                            rules_succeeded=rules_succeeded,
                            rules_failed=rules_failed,
                        )
                    )
                except Exception as e:
                    click.echo(f"  Project {proj_name} ({proj_id}) failed: {e}")
                    results.append(
                        ProjectScanResult(
                            project_id=proj_id,
                            project_name=proj_name,
                            status="failed",
                            error=str(e),
                        )
                    )
                finally:
                    advance(bar)

    results.sort(key=lambda r: r.project_name)
    return results


def _scan_gcp_project(
    project_id: str,
    project_name: str,
    credentials,
    region_filter: Optional[str],
    rules: Optional[List[Callable]] = None,
) -> Tuple[List[Finding], List[dict], int, int]:
    findings: List[Finding] = []
    skipped_rules: List[dict] = []
    rules_succeeded = 0
    rules_failed = 0

    rules_to_run = rules if rules is not None else GCP_RULES

    click.echo(f"  Scanning {project_name}")

    with ThreadPoolExecutor(max_workers=min(3, len(rules_to_run))) as executor:
        futures = {
            executor.submit(
                _run_rule_with_retry,
                rule,
                project_id,
                credentials,
                region_filter,
            ): rule
            for rule in rules_to_run
        }

        for future in as_completed(futures):
            rule = futures[future]
            rule_id = getattr(rule, "RULE_ID", rule.__name__)
            try:
                rule_findings = future.result(timeout=120)
                for f in rule_findings:
                    f.account_id = project_id
                    f.account_name = project_name
                findings.extend(rule_findings)
                rules_succeeded += 1
            except PermissionError as e:
                skipped_rules.append(
                    {
                        "rule": rule_id,
                        "missing_permissions": str(e),
                        "project_id": project_id,
                        "project_name": project_name,
                    }
                )
            except PermissionDenied as e:
                skipped_rules.append(
                    {
                        "rule": rule_id,
                        "missing_permissions": f"GCP permission denied: {e.message}",
                        "project_id": project_id,
                        "project_name": project_name,
                    }
                )
            except EnvironmentError:
                raise
            except TimeoutError:
                rules_failed += 1
                click.echo(f"  Rule timed out: {rule_id} ({project_name})")
            except GoogleAPICallError as e:
                rules_failed += 1
                click.echo(
                    f"  Rule failed: {rule_id} ({project_name}) — "
                    f"{type(e).__name__}: {getattr(e, 'message', str(e))}"
                )
            except Exception as e:
                rules_failed += 1
                click.echo(f"  Rule failed: {rule_id} ({project_name}) — {type(e).__name__}")

    if rules_succeeded == 0 and not skipped_rules and rules_failed > 0:
        raise RuntimeError(
            f"All {rules_failed} rules failed in project '{project_id}'. "
            f"This indicates a serious configuration or permissions issue."
        )

    findings.sort(key=lambda f: (f.rule_id, f.resource_id))
    return findings, skipped_rules, rules_succeeded, rules_failed
