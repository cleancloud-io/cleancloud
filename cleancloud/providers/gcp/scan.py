import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from cleancloud.providers.gcp.rules.vm_stopped import find_stopped_vms
from cleancloud.providers.gcp.session import create_gcp_session
from cleancloud.providers.gcp.validate import validate_project_params, validate_region_params

_MAX_RETRIES = 3


@dataclass
class ProjectScanResult:
    project_id: str
    project_name: str
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


GCP_RULES: List[Callable] = [
    find_unattached_disks,
    find_stopped_vms,
    find_unused_static_ips,
    find_old_snapshots,
    find_idle_sql_instances,
]


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
                wait = 2**attempt
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
) -> List[ProjectScanResult]:
    results: List[ProjectScanResult] = []
    max_workers = min(concurrency, len(project_ids))

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
                ): proj_id
                for proj_id in project_ids
            }

            for future in as_completed(futures):
                proj_id = futures[future]
                proj_name = project_name_map.get(proj_id, proj_id)
                try:
                    proj_findings, proj_skipped = future.result()
                    results.append(
                        ProjectScanResult(
                            project_id=proj_id,
                            project_name=proj_name,
                            status="success",
                            findings=proj_findings,
                            skipped_rules=proj_skipped,
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
) -> Tuple[List[Finding], List[dict]]:
    findings: List[Finding] = []
    skipped_rules: List[dict] = []
    rules_succeeded = 0
    rules_failed = 0

    click.echo(f"  Scanning {project_name}")

    with ThreadPoolExecutor(max_workers=min(3, len(GCP_RULES))) as executor:
        futures = {
            executor.submit(
                _run_rule_with_retry,
                rule,
                project_id,
                credentials,
                region_filter,
            ): rule
            for rule in GCP_RULES
        }

        for future in as_completed(futures):
            rule = futures[future]
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
                        "rule": rule.__name__,
                        "missing_permissions": str(e),
                        "project_id": project_id,
                        "project_name": project_name,
                    }
                )
            except PermissionDenied as e:
                skipped_rules.append(
                    {
                        "rule": rule.__name__,
                        "missing_permissions": f"GCP permission denied: {e.message}",
                        "project_id": project_id,
                        "project_name": project_name,
                    }
                )
            except EnvironmentError:
                raise
            except GoogleAPICallError as e:
                rules_failed += 1
                click.echo(
                    f"  Rule failed: {rule.__name__} ({project_name}) — "
                    f"{type(e).__name__}: {getattr(e, 'message', str(e))}"
                )
            except Exception as e:
                rules_failed += 1
                click.echo(f"  Rule failed: {rule.__name__} ({project_name}) — {type(e).__name__}")

    if rules_succeeded == 0 and not skipped_rules and rules_failed > 0:
        raise RuntimeError(
            f"All {rules_failed} rules failed in project '{project_id}'. "
            f"This indicates a serious configuration or permissions issue."
        )

    return findings, skipped_rules
