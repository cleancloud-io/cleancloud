"""
Parity test: assert Azure role template files contain every action required
by the corresponding rule implementations.

Rationale: the existing read-only safety test (`test_azure_role_definition_readonly.py`)
ensures no mutating actions slip in, but does NOT verify coverage. This test catches
the complementary failure mode — a required action silently omitted from the shipped role,
leaving users with an "official" role that produces coverage gaps at runtime.
"""

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Required actions per role file — derived from rule headers and doctor probes
# ---------------------------------------------------------------------------

HYGIENE_REQUIRED_ACTIONS = {
    # azure.compute.managed_disk.unattached
    "Microsoft.Compute/disks/read",
    # azure.compute.snapshot.old
    "Microsoft.Compute/snapshots/read",
    # azure.vm.stopped_not_deallocated — list + instance view (PowerState)
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/instanceView/action",
    # azure.network.public_ip.unused
    "Microsoft.Network/publicIPAddresses/read",
    # azure.load_balancer.no_backends
    "Microsoft.Network/loadBalancers/read",
    # azure.app_gateway.no_backends
    "Microsoft.Network/applicationGateways/read",
    # azure.vnet_gateway.idle
    "Microsoft.Network/virtualNetworkGateways/read",
    "Microsoft.Network/connections/read",
    # azure.app_service_plan.empty
    "Microsoft.Web/serverfarms/read",
    "Microsoft.Web/serverfarms/sites/read",
    # azure.app_service.idle — includes WebJobs enumeration
    "Microsoft.Web/sites/read",
    "Microsoft.Web/sites/webJobs/read",
    # azure.container_registry.unused
    "Microsoft.ContainerRegistry/registries/read",
    # azure.sql.database.idle
    "Microsoft.Sql/servers/read",
    "Microsoft.Sql/servers/databases/read",
    # metrics (sql, app service, vnet gateway, container registry)
    "Microsoft.Insights/metrics/read",
    # subscription + resource discovery
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/resources/read",
}

AI_REQUIRED_ACTIONS = {
    # azure.aml.compute.idle, azure.ml.compute_instance.idle
    "Microsoft.MachineLearningServices/workspaces/read",
    "Microsoft.MachineLearningServices/workspaces/computes/read",
    # azure.ml.online_endpoint.idle — endpoint list + deployment reads
    "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
    "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read",
    # azure.openai.provisioned_deployment.idle
    "Microsoft.CognitiveServices/accounts/read",
    "Microsoft.CognitiveServices/accounts/deployments/read",
    # azure.ai_search.idle (management-plane; data-plane RBAC is separate)
    "Microsoft.Search/searchServices/read",
    # metrics for all AI rules
    "Microsoft.Insights/metrics/read",
}

ROLE_PARITY: list[tuple[Path, set[str]]] = [
    (Path("security/azure/hygiene-readonly-role.json"), HYGIENE_REQUIRED_ACTIONS),
    (Path("security/azure/ai-readonly-role.json"), AI_REQUIRED_ACTIONS),
]


def _actions_in_role(role_path: Path) -> set[str]:
    role = json.loads(role_path.read_text())
    actions: set[str] = set()
    for perm in role.get("Permissions", []):
        for action in perm.get("Actions", []):
            actions.add(action)
    return actions


@pytest.mark.safety
@pytest.mark.azure
@pytest.mark.parametrize(
    "role_path,required", ROLE_PARITY, ids=lambda x: x.name if isinstance(x, Path) else "required"
)
def test_azure_role_contains_required_actions(role_path, required):
    """
    Assert that every runtime-required action is present in the shipped role template.
    Missing actions cause silent coverage gaps at runtime — rules skip resources
    without any error when the required permission is absent.
    """
    actual = _actions_in_role(role_path)
    missing = required - actual
    assert not missing, (
        f"{role_path.name} is missing {len(missing)} required action(s):\n"
        + "\n".join(f"  - {a}" for a in sorted(missing))
        + "\nAdd them to the role template to prevent silent coverage gaps at runtime."
    )
