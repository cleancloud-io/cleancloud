import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

from cleancloud.doctor.common import fail, info, success, warn


def detect_azure_auth_method() -> tuple[str, str, dict]:
    # Check environment variables to determine method
    has_federated_token = os.getenv("AZURE_FEDERATED_TOKEN_FILE") is not None
    has_client_secret = os.getenv("AZURE_CLIENT_SECRET") is not None
    has_client_id = os.getenv("AZURE_CLIENT_ID") is not None
    has_tenant_id = os.getenv("AZURE_TENANT_ID") is not None

    metadata = {"recommended": False, "ci_cd_ready": False, "security_grade": "unknown"}

    # OIDC / Workload Identity Federation (GitHub Actions, Azure DevOps)
    if has_federated_token and has_client_id and has_tenant_id:
        metadata.update(
            {
                "recommended": True,
                "ci_cd_ready": True,
                "security_grade": "excellent",
                "credential_lifetime": "1 hour (temporary)",
                "rotation_required": False,
                "uses_secret": False,  # nosec B105 - metadata flag, not a password
            }
        )

        if has_client_secret:
            metadata["warning"] = "AZURE_CLIENT_SECRET set but not used (OIDC takes precedence)"

        return "oidc", "OIDC (Workload Identity Federation)", metadata

    # Service Principal with Client Secret (legacy)
    elif has_client_secret and has_client_id and has_tenant_id:
        metadata.update(
            {
                "recommended": False,
                "ci_cd_ready": False,
                "security_grade": "poor",
                "credential_lifetime": "long-lived (client secret)",
                "rotation_required": True,
                "rotation_interval": "90 days or per policy",
                "uses_secret": True,  # nosec B105 - metadata flag, not a password
            }
        )
        return "client_secret", "Service Principal (Client Secret)", metadata

    # Azure CLI (local development)
    elif not has_client_id and not has_client_secret:
        metadata.update(
            {
                "recommended": False,
                "ci_cd_ready": False,
                "security_grade": "acceptable",
                "credential_lifetime": "Azure CLI session",
                "rotation_required": False,
                "uses_secret": False,  # nosec B105 - metadata flag, not a password
            }
        )
        return "azure_cli", "Azure CLI", metadata

    # Managed Identity (Azure VMs, App Service, etc.)
    # Note: This is hard to detect without actually trying, but we can infer
    else:
        metadata.update(
            {
                "recommended": True,
                "ci_cd_ready": False,
                "security_grade": "excellent",
                "credential_lifetime": "temporary (auto-rotated)",
                "rotation_required": False,
                "uses_secret": False,  # nosec B105 - metadata flag, not a password
            }
        )
        return "managed_identity", "Managed Identity", metadata


def run_azure_doctor() -> None:
    info("")
    info("=" * 70)
    info("AZURE ENVIRONMENT VALIDATION")
    info("=" * 70)
    info("")

    # Step 1: Detect authentication method
    info("Step 1: Azure Credential Resolution")
    info("-" * 70)

    method_id, description, metadata = detect_azure_auth_method()

    # Display auth method with context
    info(f"Authentication Method: {description}")

    if metadata.get("credential_lifetime"):
        info(f"  Lifetime: {metadata['credential_lifetime']}")

    if metadata.get("rotation_required"):
        info(f"  Rotation Required: Yes (every {metadata.get('rotation_interval', '90 days')})")
    else:
        info("  Rotation Required: No")

    if metadata.get("uses_secret") is not None:
        if metadata["uses_secret"]:
            warn("  Uses Secret: Yes (stored credential)")
        else:
            success("  Uses Secret: No (secretless)")

    # Security assessment
    info("")
    security_grade = metadata.get("security_grade", "unknown")

    if security_grade == "excellent":
        success("Security Grade: EXCELLENT")
        success("  - No client secrets stored")
        success("  - Temporary credentials")
        success("  - Auto-rotated")

    elif security_grade == "good":
        success("Security Grade: GOOD")
        info("  - Temporary credentials")

    elif security_grade == "acceptable":
        warn("Security Grade: ACCEPTABLE")
        info("  Suitable for local development")
        if method_id == "azure_cli":
            info("  Azure CLI authentication (interactive)")

    elif security_grade == "poor":
        warn("Security Grade: POOR")
        warn("  - Long-lived client secret")
        warn("  - Requires manual rotation")
        warn("  - High blast radius if compromised")
        info("")
        info("  Recommendation for CI/CD:")
        info("    Switch to OIDC (Workload Identity Federation)")
        info("    See: https://docs.cleancloud.io/azure#oidc")

    else:
        info(f"Security Grade: {security_grade.upper()}")

    # CI/CD readiness
    info("")
    if metadata.get("ci_cd_ready"):
        success("CI/CD Ready: YES")
        success("  Suitable for production CI/CD pipelines")
    else:
        if method_id == "azure_cli":
            info("CI/CD Ready: NO (Local development only)")
            info("  Azure CLI is interactive and not suitable for CI/CD")
        else:
            warn("CI/CD Ready: NO")
            warn("  Client secrets not recommended for automated pipelines")

    # Compliance notes
    info("")
    if metadata.get("security_grade") in ("excellent", "good"):
        success("Compliance: SOC2/ISO27001 Compatible")
    elif metadata.get("security_grade") == "acceptable":
        info("Compliance: Acceptable for development environments")
    else:
        warn("Compliance: May not meet enterprise security requirements")

    # Display configured environment
    info("")
    client_id = os.getenv("AZURE_CLIENT_ID")
    tenant_id = os.getenv("AZURE_TENANT_ID")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    if client_id:
        info(f"Client ID: {client_id}")

    if tenant_id:
        info(f"Tenant ID: {tenant_id}")

    if subscription_id:
        info(f"Subscription Filter: {subscription_id}")

    # Warning if stale env var
    if metadata.get("warning"):
        info("")
        warn(metadata["warning"])

    # Step 2: Authenticate
    info("")
    info("Step 2: Credential Acquisition")
    info("-" * 70)

    try:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)

        # Force token acquisition to verify credentials work
        token = credential.get_token("https://management.azure.com/.default")
        success("Azure credentials acquired successfully")

        # Calculate time until expiry (expires_on is Unix timestamp)
        import time

        current_time = int(time.time())
        expires_in_minutes = (token.expires_on - current_time) // 60
        info(f"  Token expires in: ~{expires_in_minutes} minutes")

    except Exception:
        info("")
        warn("Azure credentials not found or could not be acquired.")
        info("")
        info("To configure credentials, choose one of:")
        info(
            "  - Azure Cloud Shell:      credentials are injected automatically from your portal session"
        )
        info("  - Local Azure CLI:        run `az login`")
        info("  - CI/CD (Workload ID):    see docs/azure.md for Workload Identity Federation setup")
        info(
            "  - Environment variables:  set AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET"
        )
        info("")
        info("RBAC permissions required (assign to your service principal or user):")
        info("  Built-in role: Reader  (at subscription scope)")
        info("")
        info("  Or the individual permissions CleanCloud uses:")
        info("  Microsoft.Compute/disks/read")
        info("  Microsoft.Compute/snapshots/read")
        info("  Microsoft.Compute/virtualMachines/read")
        info("  Microsoft.Compute/virtualMachines/instanceView/action")
        info("  Microsoft.Network/publicIPAddresses/read")
        info("  Microsoft.Network/loadBalancers/read")
        info("  Microsoft.Network/applicationGateways/read")
        info("  Microsoft.Network/virtualNetworkGateways/read")
        info("  Microsoft.Network/connections/read")
        info("  Microsoft.Web/serverfarms/read")
        info("  Microsoft.Web/serverfarms/sites/read")
        info("  Microsoft.Web/sites/read")
        info("  Microsoft.Web/sites/webJobs/read")
        info("  Microsoft.ContainerRegistry/registries/read")
        info("  Microsoft.Sql/servers/read")
        info("  Microsoft.Sql/servers/databases/read")
        info("  Microsoft.Insights/metrics/read")
        info("  Microsoft.Resources/subscriptions/read")
        info("  Microsoft.Resources/resources/read")
        info("  AI/ML rules (opt-in via --category ai):")
        info("    - Microsoft.MachineLearningServices/workspaces/read")
        info("    - Microsoft.MachineLearningServices/workspaces/computes/read")
        info("    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read")
        info("    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read")
        info("    - Microsoft.CognitiveServices/accounts/read")
        info("    - Microsoft.CognitiveServices/accounts/deployments/read")
        info("    - Microsoft.Search/searchServices/read")
        info("    - Microsoft.Insights/metrics/read")
        info("")
        info("Copy the ready-to-use RBAC setup from:")
        info("  docs/azure.md  (Workload Identity + Reader role assignment)")
        fail("Azure authentication failed — configure credentials and re-run doctor")

    # Step 3: Subscription access validation
    info("")
    info("Step 3: Subscription Access Validation")
    info("-" * 70)

    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        if not subscriptions:
            fail("No accessible Azure subscriptions found")

        success(f"Accessible subscriptions: {len(subscriptions)}")

        # List subscriptions
        for sub in subscriptions:
            info(f"  • {sub.display_name} ({sub.subscription_id})")

        if subscription_id:
            # Check if filtered subscription is accessible
            filtered_sub = next(
                (s for s in subscriptions if s.subscription_id == subscription_id), None
            )

            if filtered_sub:
                info("")
                success(f"Subscription filter matched: {filtered_sub.display_name}")
            else:
                warn(f"Subscription filter {subscription_id} not found in accessible subscriptions")

    except Exception as e:
        fail(f"Azure subscription validation failed: {e}")

    # Step 4: Permission validation
    info("")
    info("Step 4: Permission Validation")
    info("-" * 70)

    # For Azure, we've already validated subscription access
    # Reader role gives us all the permissions we need
    success("Subscription read access confirmed")
    info("  Reader role provides all required permissions:")
    info("    - Microsoft.Compute/disks/read")
    info("    - Microsoft.Compute/snapshots/read")
    info("    - Microsoft.Compute/virtualMachines/read")
    info("    - Microsoft.Compute/virtualMachines/instanceView/action")
    info("    - Microsoft.Network/publicIPAddresses/read")
    info("    - Microsoft.Network/loadBalancers/read")
    info("    - Microsoft.Network/applicationGateways/read")
    info("    - Microsoft.Network/virtualNetworkGateways/read")
    info("    - Microsoft.Network/connections/read")
    info("    - Microsoft.Web/serverfarms/read")
    info("    - Microsoft.Web/serverfarms/sites/read")
    info("    - Microsoft.Web/sites/read")
    info("    - Microsoft.Web/sites/webJobs/read")
    info("    - Microsoft.ContainerRegistry/registries/read")
    info("    - Microsoft.Sql/servers/read")
    info("    - Microsoft.Sql/servers/databases/read")
    info("    - Microsoft.Insights/metrics/read")
    info("    - Microsoft.Resources/subscriptions/read")
    info("    - Microsoft.Resources/resources/read")
    info("  AI/ML rules (opt-in via --category ai):")
    info("    - Microsoft.MachineLearningServices/workspaces/read")
    info("    - Microsoft.MachineLearningServices/workspaces/computes/read")
    info("    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read")
    info("    - Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read")
    info("    - Microsoft.CognitiveServices/accounts/read")
    info("    - Microsoft.CognitiveServices/accounts/deployments/read")
    info("    - Microsoft.Search/searchServices/read")
    info("    - Microsoft.Insights/metrics/read")

    # Probe the two permissions that custom CleanCloudReadOnly roles historically omitted.
    # Reader (built-in) includes these; custom least-privilege roles may not.
    info("")
    info("Step 5: Runtime Permission Probes (custom-role gap check)")
    info("-" * 70)

    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.web import WebSiteManagementClient

    compute_client = ComputeManagementClient(credential, subscriptions[0].subscription_id)
    web_client = WebSiteManagementClient(credential, subscriptions[0].subscription_id)

    # Probe: Microsoft.Compute/virtualMachines/instanceView/action
    # Required by azure.vm.stopped_not_deallocated — reads PowerState from instance view statuses.
    try:
        _vms = list(compute_client.virtual_machines.list_all())
        _first_vm = next(iter(_vms), None)
        if _first_vm:
            _rg = _first_vm.id.split("/")[
                _first_vm.id.lower().split("/").index("resourcegroups") + 1
            ]
            compute_client.virtual_machines.get(_rg, _first_vm.name, expand="instanceView")
            success("Microsoft.Compute/virtualMachines/instanceView/action")
        else:
            info(
                "Microsoft.Compute/virtualMachines/instanceView/action — not tested (no VMs found to probe)"
            )
    except Exception as e:
        if "AuthorizationFailed" in str(e) or "403" in str(e):
            warn(f"Microsoft.Compute/virtualMachines/instanceView/action — DENIED: {e}")
            warn(
                "  azure.vm.stopped_not_deallocated will skip all VMs — add this action to your custom role"
            )
        else:
            info(f"Microsoft.Compute/virtualMachines/instanceView/action — could not probe: {e}")

    # Probe: Microsoft.Web/sites/webJobs/read
    # Required by azure.app_service.idle — enumerates WebJobs to avoid false positives.
    try:
        _sites = list(web_client.web_apps.list())
        _first_site = next(iter(_sites), None)
        if _first_site:
            _rg = _first_site.id.split("/")[
                _first_site.id.lower().split("/").index("resourcegroups") + 1
            ]
            list(web_client.web_apps.list_web_jobs(_rg, _first_site.name))
            success("Microsoft.Web/sites/webJobs/read")
        else:
            info("Microsoft.Web/sites/webJobs/read — not tested (no App Services found to probe)")
    except Exception as e:
        if "AuthorizationFailed" in str(e) or "403" in str(e):
            warn(f"Microsoft.Web/sites/webJobs/read — DENIED: {e}")
            warn(
                "  azure.app_service.idle will skip all App Services — add this action to your custom role"
            )
        else:
            info(f"Microsoft.Web/sites/webJobs/read — could not probe: {e}")

    # Summary
    info("")
    info("=" * 70)
    info("VALIDATION SUMMARY")
    info("=" * 70)

    info(f"Authentication: {description}")
    info(f"Security Grade: {security_grade.upper()}")
    info(f"Subscriptions: {len(subscriptions)} accessible")

    if subscription_id:
        info(f"Filtered to: {subscription_id}")

    info("")
    success("AZURE ENVIRONMENT READY FOR CLEANCLOUD")
    info("")
    info("Tip: To also validate AI/ML permissions (Azure ML rules), run:")
    info("  cleancloud doctor --provider azure --category ai")
    info("=" * 70)
    info("")


def run_azure_ai_doctor(subscription_id: str = None) -> None:
    """Validate Azure permissions for --category ai (AML compute, ML compute instance, and Azure OpenAI provisioned deployment rules)."""
    info("")
    info("=" * 70)
    info("AZURE AI/ML PERMISSION VALIDATION")
    info("=" * 70)
    info("")
    info("Validating permissions for: cleancloud scan --provider azure --category ai")
    info("")

    try:
        from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces

        credential = DefaultAzureCredential()
    except Exception as e:
        fail(f"Azure authentication failed — configure credentials and re-run doctor: {e}")
        return

    # Resolve a subscription to test against
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())
        if not subscriptions:
            fail("No accessible Azure subscriptions found")
            return
        test_sub = subscription_id or subscriptions[0].subscription_id
        success(f"Using subscription: {test_sub}")
    except Exception as e:
        fail(f"Failed to list subscriptions: {e}")
        return

    info("")
    info("Permission Checks")
    info("-" * 70)

    permissions_tested = []
    permissions_failed = []

    # Check: Microsoft.MachineLearningServices/workspaces/read
    try:
        ml_client = AzureMachineLearningWorkspaces(
            credential=credential,
            subscription_id=test_sub,
        )
        workspaces = list(ml_client.workspaces.list_by_subscription())
        permissions_tested.append("Microsoft.MachineLearningServices/workspaces/read")
        success(
            f"Microsoft.MachineLearningServices/workspaces/read "
            f"({len(workspaces)} workspace(s) found)"
        )
    except Exception as e:
        permissions_failed.append(("Microsoft.MachineLearningServices/workspaces/read", str(e)))
        warn(f"Microsoft.MachineLearningServices/workspaces/read — {e}")
        workspaces = []

    # Check: Microsoft.MachineLearningServices/workspaces/computes/read
    if workspaces:
        try:
            ws = workspaces[0]
            rg = ws.id.split("/")[ws.id.lower().split("/").index("resourcegroups") + 1]
            list(ml_client.compute.list(rg, ws.name))
            permissions_tested.append("Microsoft.MachineLearningServices/workspaces/computes/read")
            success("Microsoft.MachineLearningServices/workspaces/computes/read")
        except Exception as e:
            permissions_failed.append(
                ("Microsoft.MachineLearningServices/workspaces/computes/read", str(e))
            )
            warn(f"Microsoft.MachineLearningServices/workspaces/computes/read — {e}")
    else:
        info(
            "  Skipping computes/read check — no workspaces found to test against "
            "(permission may still be present)"
        )

    # Check: Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read (list endpoints)
    _endpoints = []
    if workspaces:
        try:
            ws = workspaces[0]
            rg = ws.id.split("/")[ws.id.lower().split("/").index("resourcegroups") + 1]
            # Attempt to list online endpoints to validate permission
            _endpoints = list(ml_client.online_endpoints.list(rg, ws.name))
            permissions_tested.append(
                "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read"
            )
            success("Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read")
        except Exception as e:
            permissions_failed.append(
                (
                    "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
                    str(e),
                )
            )
            warn(f"Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read — {e}")
    else:
        info(
            "  Skipping onlineEndpoints/read check — no workspaces found to test against "
            "(permission may still be present)"
        )

    # Check: Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read
    # Required by azure.ml.online_endpoint.idle to read instance SKU and replica counts.
    if workspaces and _endpoints:
        try:
            ws = workspaces[0]
            rg = ws.id.split("/")[ws.id.lower().split("/").index("resourcegroups") + 1]
            ep_name = _endpoints[0].name
            list(ml_client.online_deployments.list(rg, ws.name, ep_name))
            permissions_tested.append(
                "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read"
            )
            success("Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read")
        except Exception as e:
            permissions_failed.append(
                (
                    "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read",
                    str(e),
                )
            )
            warn(
                f"Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read — {e}"
            )
    elif workspaces:
        info(
            "  Skipping onlineEndpoints/deployments/read check — no endpoints found to test against "
            "(permission may still be present)"
        )
    else:
        info(
            "  Skipping onlineEndpoints/deployments/read check — no workspaces found to test against "
            "(permission may still be present)"
        )

    # Check: Microsoft.CognitiveServices/accounts/read (for Azure OpenAI provisioned deployments)
    try:
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

        cs_client = CognitiveServicesManagementClient(
            credential=credential,
            subscription_id=test_sub,
        )
        accounts = list(cs_client.accounts.list())
        permissions_tested.append("Microsoft.CognitiveServices/accounts/read")
        success(f"Microsoft.CognitiveServices/accounts/read " f"({len(accounts)} account(s) found)")

        # Check deployments/read on the first OpenAI/AIServices account if available
        openai_accounts = [
            a for a in accounts if getattr(a, "kind", None) in ("OpenAI", "AIServices")
        ]
        if openai_accounts:
            try:
                acct = openai_accounts[0]
                rg = acct.id.split("/")[acct.id.lower().split("/").index("resourcegroups") + 1]
                list(cs_client.deployments.list(rg, acct.name))
                permissions_tested.append("Microsoft.CognitiveServices/accounts/deployments/read")
                success("Microsoft.CognitiveServices/accounts/deployments/read")
            except Exception as e:
                permissions_failed.append(
                    ("Microsoft.CognitiveServices/accounts/deployments/read", str(e))
                )
                warn(f"Microsoft.CognitiveServices/accounts/deployments/read — {e}")
        else:
            info(
                "  Skipping deployments/read check — no OpenAI/AIServices accounts found to test "
                "against (permission may still be present)"
            )

    except Exception as e:
        permissions_failed.append(("Microsoft.CognitiveServices/accounts/read", str(e)))
        warn(f"Microsoft.CognitiveServices/accounts/read — {e}")

    # Check: Microsoft.Search/searchServices/read (AI Search services)
    try:
        from azure.mgmt.search import SearchManagementClient

        search_client = SearchManagementClient(credential=credential, subscription_id=test_sub)
        svcs = list(search_client.services.list_by_subscription())
        permissions_tested.append("Microsoft.Search/searchServices/read")
        success(f"Microsoft.Search/searchServices/read ({len(svcs)} service(s) found)")
    except Exception as e:
        permissions_failed.append(("Microsoft.Search/searchServices/read", str(e)))
        warn(f"Microsoft.Search/searchServices/read — {e}")

    # Data-plane RBAC warning for azure.ai_search.idle
    # The rule calls Azure AI Search data-plane APIs (list indexes, indexers, etc.) using
    # keyless RBAC auth. Management-plane Reader is not sufficient — the identity also needs
    # Search Index Data Reader (or Search Service Contributor) assigned on each Search service.
    # This cannot be probed here without knowing a service endpoint, so we always emit a notice.
    info("")
    warn("azure.ai_search.idle — data-plane RBAC required (not verified here)")
    info("  The AI Search idle rule calls data-plane APIs to check structural emptiness.")
    info("  Management-plane Reader alone is not sufficient. Assign one of:")
    info("    - Search Index Data Reader  (read-only, recommended)")
    info("    - Search Service Contributor  (broader access)")
    info("  Scope: each Azure AI Search service (or resource group / subscription).")
    info("  Without this, the rule skips all Search services silently.")
    info("  Assign with:")
    info("    az role assignment create \\")
    info('      --role "Search Index Data Reader" \\')
    info("      --assignee <APP_ID> \\")
    info(
        "      --scope /subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.Search/searchServices/<NAME>"
    )

    # Check: Microsoft.Insights/metrics/read (already required by hygiene rules)
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor = MonitorManagementClient(credential=credential, subscription_id=test_sub)
        # A lightweight call — list metric definitions for a subscription-level scope
        monitor.metric_definitions.list(
            f"/subscriptions/{test_sub}",
        )
        permissions_tested.append("Microsoft.Insights/metrics/read")
        success("Microsoft.Insights/metrics/read")
    except Exception as e:
        permissions_failed.append(("Microsoft.Insights/metrics/read", str(e)))
        warn(f"Microsoft.Insights/metrics/read — {e}")

    info("")
    info("=" * 70)
    total = len(permissions_tested) + len(permissions_failed)
    info(f"Permissions: {len(permissions_tested)}/{total} passed")

    if permissions_failed:
        info("")
        for perm, _ in permissions_failed:
            warn(f"  missing: {perm}")
        info("")
        info("Assign the AI role to your service principal:")
        info("  az role definition create --role-definition security/azure/ai-readonly-role.json")
        info('  az role assignment create --assignee <APP_ID> --role "CleanCloudAIReadOnly" \\')
        info("    --scope /subscriptions/<SUBSCRIPTION_ID>")
        info("Then re-run: cleancloud doctor --provider azure --category ai")
        info("")
        warn("AZURE AI/ML PERMISSIONS INCOMPLETE")
    else:
        info("")
        success("AZURE AI/ML PERMISSIONS READY")
        info("Run: cleancloud scan --provider azure --category ai")
    info("=" * 70)
    info("")
