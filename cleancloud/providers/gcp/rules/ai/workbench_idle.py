"""
Rule: gcp.vertex.workbench.idle

    (spec -- docs/specs/gcp/ai/workbench_idle.md)

Intent:
    Detect Vertex AI Workbench instances that are provably still running and have
    documented first-party evidence of notebook/kernel inactivity over a conservative
    review window.

    This rule is deliberately precision-first. It is a review-candidate rule only.
    It is not proof that an instance is safe to stop, not proof that no scheduled or
    background work exists, and not proof of a specific monthly saving.

Current canonical status:
    EMITTING_DISABLED. No qualifying canonical signal exists that exposes per-instance
    last kernel activity or a kernel-idle time series suitable for this rule. The rule
    must not emit findings from control-plane timestamps alone.

    updateTime and createTime are NOT canonical idle signals. Neither is
    CPU utilization or instance age. No qualifying signal path is currently established.

Discovery failure taxonomy:
    404: API not enabled for the project; provably no instances.
    400: endpoint or wildcard unsupported; discovery incomplete.
    5xx: transient server error; discovery incomplete.
    network error: transport failure; discovery incomplete.
    unreachable[]: API-reported location gaps.

Future activation path:
    When Google documents a qualifying per-instance Workbench-attributable signal
    (Cloud Logging kernel/session activity logs, or a Cloud Monitoring metric with
    documented kernel-idle semantics), the implementation can continue from the
    candidate list and apply signal evaluation for reachable instances.

APIs:
    - notebooks.googleapis.com/v2: projects/{project}/locations/-/instances
"""

import re
import warnings
from typing import List, Optional

from google.auth.transport.requests import AuthorizedSession

from cleancloud.core.finding import Finding

RULE_METADATA = {
    "id": "gcp.vertex.workbench.idle",
    "category": "ai",
    "service": "notebooks",
    "cost_impact": "high",
}

# Exact documented resource-name pattern (spec 3.1, 7):
#   projects/{projectId}/locations/{location}/instances/{instanceId}
# All four non-empty path segments must be present.
_INSTANCE_NAME_RE = re.compile(r"^projects/[^/]+/locations/[^/]+/instances/[^/]+$")


def find_idle_workbench_instances(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find Vertex AI Workbench instances with documented kernel inactivity.

    Currently EMITTING_DISABLED: no qualifying canonical signal exists for
    per-instance kernel activity. updateTime and createTime MUST NOT be used
    as idle signals. Always returns an empty list.

    Performs full candidate classification and surfaces results via warnings:
      - PARTIAL scope: unreachable[] locations or discovery failures warn once.
      - NOT_EVALUABLE: ACTIVE candidates with NO_SIGNAL warn with resource names.
      - INVALID resources: malformed name or missing state; counted but not warned.
      - OUT_OF_SCOPE: non-ACTIVE instances; excluded silently.

    IAM permissions required:
        notebooks.instances.list (roles/notebooks.viewer)
    """
    if idle_days < 1:
        raise ValueError(f"idle_days must be >= 1, got {idle_days!r}")

    session = AuthorizedSession(credentials)
    raw_instances, unreachable_locations, discovery_failed = _list_instances(session, project_id)

    # --- Partial scan scope ---
    # The spec defines PARTIAL exclusively from discovery-layer reachability:
    # unreachable[] locations reported by the API (section 12.1, 12.2.7).
    # 400/5xx/network errors (discovery_failed) make enumeration incomplete but
    # are NOT defined as PARTIAL by the spec; they get a separate warning.
    if unreachable_locations:
        warnings.warn(
            f"gcp.vertex.workbench.idle: scan scope PARTIAL for project '{project_id}'"
            f" — unreachable locations: {unreachable_locations}",
            UserWarning,
            stacklevel=2,
        )

    if discovery_failed:
        warnings.warn(
            f"gcp.vertex.workbench.idle: discovery incomplete for project '{project_id}'"
            f" — transport or server error encountered; scan results may be incomplete",
            UserWarning,
            stacklevel=2,
        )

    # --- Classify resource records ---
    # INVALID: resource name absent/malformed or state absent/empty — counted.
    # OUT_OF_SCOPE: valid name+state but not ACTIVE — excluded silently.
    excluded_invalid_count = 0
    candidate_resources: list[dict] = []

    for raw in raw_instances:
        name = (raw.get("name") or "").strip()
        state = (raw.get("state") or "").strip()

        if not name or not _INSTANCE_NAME_RE.match(name):
            excluded_invalid_count += 1
            continue

        if not state:
            excluded_invalid_count += 1
            continue

        # OUT_OF_SCOPE: valid but not ACTIVE — excluded silently, not counted.
        if state != "ACTIVE":
            continue

        # location is segment index 3 of the validated name.
        location = name.split("/")[3]

        # Region filter: exact string equality, no aliasing or case folding.
        if region_filter and location != region_filter:
            continue

        candidate_resources.append({"name": name, "location": location})

    # --- INVALID count ---
    # Surface the exact count of records excluded as INVALID so operators can
    # detect data-quality issues without the rule silently discarding records.
    if excluded_invalid_count:
        warnings.warn(
            f"gcp.vertex.workbench.idle: {excluded_invalid_count} resource record(s)"
            f" in project '{project_id}' excluded as INVALID"
            f" (malformed resource name or missing state field)",
            UserWarning,
            stacklevel=2,
        )

    # --- NOT_EVALUABLE: ACTIVE candidates exist but no canonical signal ---
    # Warn with a capped list of resource names (first 5 + overflow count) so
    # the warning stays readable even in large projects.
    if candidate_resources:
        _cap = 5
        shown = [r["name"] for r in candidate_resources[:_cap]]
        overflow = len(candidate_resources) - _cap
        name_summary = ", ".join(shown)
        if overflow > 0:
            name_summary += f", ... (+{overflow} more)"
        warnings.warn(
            f"gcp.vertex.workbench.idle: {len(candidate_resources)} ACTIVE instance(s)"
            f" in project '{project_id}' cannot be evaluated (NO_SIGNAL) —"
            f" no qualifying canonical kernel-activity signal exists;"
            f" rule is EMITTING_DISABLED. Instances: {name_summary}",
            UserWarning,
            stacklevel=2,
        )

    return []


find_idle_workbench_instances.RULE_ID = "gcp.vertex.workbench.idle"


def _list_instances(
    session: AuthorizedSession,
    project_id: str,
) -> tuple[list, list, bool]:
    """
    List all Vertex AI Workbench instances across all locations using the v2 API.

    Uses the locations/- wildcard for a single paginated call covering all regions.
    Exhausts pagination via nextPageToken.
    Collects unreachable[] locations reported by the API.

    Returns (instances, unreachable_locations, discovery_failed):
        instances:             raw instance dicts from the API
        unreachable_locations: locations the API reported as unreachable
        discovery_failed:      True when a transport/server error made enumeration
                               incomplete.

    Error handling:
        403: raises PermissionError (user-actionable; propagates up)
        404: API not enabled; returns ([], [], False) — clean empty scope
        400: bad request or wildcard unsupported; warns, returns ([], [], True)
        5xx: transient server error; warns, returns partial results with True
        network error: warns, returns partial results with True
    """
    results: list = []
    unreachable: list = []
    discovery_failed = False
    url = f"https://notebooks.googleapis.com/v2" f"/projects/{project_id}/locations/-/instances"
    params: dict = {"pageSize": 100}

    while True:
        try:
            resp = session.get(url, params=params)
        except Exception as exc:
            warnings.warn(
                f"gcp.vertex.workbench.idle: network error fetching instances for "
                f"project '{project_id}' ({type(exc).__name__}: {exc}) — "
                "discovery incomplete",
                UserWarning,
                stacklevel=3,
            )
            discovery_failed = True
            break

        if resp.status_code == 403:
            raise PermissionError(
                "notebooks.instances.list permission required (roles/notebooks.viewer)"
            )

        if resp.status_code == 404:
            # 404 = Notebooks API not enabled for this project.
            # Assumption: if the API is not enabled, no instances can exist.
            # Treated as a clean empty scope (FULL, EVALUABLE).
            # A warning is emitted so callers are aware of the assumption.
            warnings.warn(
                f"gcp.vertex.workbench.idle: Notebooks API not enabled for project"
                f" '{project_id}' (HTTP 404) — assuming no instances exist;"
                f" scope treated as FULL",
                UserWarning,
                stacklevel=3,
            )
            return [], [], False

        if resp.status_code == 400:
            warnings.warn(
                f"gcp.vertex.workbench.idle: HTTP 400 from Notebooks API for project "
                f"'{project_id}' — discovery incomplete",
                UserWarning,
                stacklevel=3,
            )
            return [], [], True

        if resp.status_code >= 500:
            warnings.warn(
                f"gcp.vertex.workbench.idle: server error (HTTP {resp.status_code}) "
                f"for project '{project_id}' — discovery incomplete",
                UserWarning,
                stacklevel=3,
            )
            discovery_failed = True
            break

        resp.raise_for_status()
        data = resp.json()

        results.extend(data.get("instances", []))

        for loc in data.get("unreachable", []):
            if loc and loc not in unreachable:
                unreachable.append(loc)

        next_token = data.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token

    return results, unreachable, discovery_failed
