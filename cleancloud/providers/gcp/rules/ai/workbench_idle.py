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
    as idle signals.

    Always returns an empty list until a qualifying signal is available.

    IAM permissions required:
        notebooks.instances.list (roles/notebooks.viewer)
    """
    if idle_days < 1:
        raise ValueError(f"idle_days must be >= 1, got {idle_days!r}")

    session = AuthorizedSession(credentials)
    _list_instances(session, project_id)
    return []


find_idle_workbench_instances.RULE_ID = "gcp.vertex.workbench.idle"


def _list_instances(
    session: AuthorizedSession,
    project_id: str,
) -> tuple:
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
