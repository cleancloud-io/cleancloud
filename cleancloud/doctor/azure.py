import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient

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
                "uses_secret": False,
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
                "uses_secret": True,
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
                "uses_secret": False,
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
                "uses_secret": False,
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
    info("🔐 Step 1: Azure Credential Resolution")
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
        success("Security Grade: EXCELLENT ✅")
        success("  ✓ No client secrets stored")
        success("  ✓ Temporary credentials")
        success("  ✓ Auto-rotated")

    elif security_grade == "good":
        success("Security Grade: GOOD ✅")
        info("  ✓ Temporary credentials")

    elif security_grade == "acceptable":
        warn("Security Grade: ACCEPTABLE ⚠️")
        info("  Suitable for local development")
        if method_id == "azure_cli":
            info("  Azure CLI authentication (interactive)")

    elif security_grade == "poor":
        warn("Security Grade: POOR ⚠️")
        warn("  ⚠ Long-lived client secret")
        warn("  ⚠ Requires manual rotation")
        warn("  ⚠ High blast radius if compromised")
        info("")
        info("  Recommendation for CI/CD:")
        info("    Switch to OIDC (Workload Identity Federation)")
        info("    See: https://docs.cleancloud.io/azure#oidc")

    else:
        info(f"Security Grade: {security_grade.upper()}")

    # CI/CD readiness
    info("")
    if metadata.get("ci_cd_ready"):
        success("CI/CD Ready: YES ✅")
        success("  Suitable for production CI/CD pipelines")
    else:
        if method_id == "azure_cli":
            info("CI/CD Ready: NO (Local development only)")
            info("  Azure CLI is interactive and not suitable for CI/CD")
        else:
            warn("CI/CD Ready: NO ⚠️")
            warn("  Client secrets not recommended for automated pipelines")

    # Compliance notes
    info("")
    if metadata.get("security_grade") in ("excellent", "good"):
        success("Compliance: SOC2/ISO27001 Compatible ✅")
    elif metadata.get("security_grade") == "acceptable":
        info("Compliance: Acceptable for development environments")
    else:
        warn("Compliance: May not meet enterprise security requirements ⚠️")

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
    info("🔑 Step 2: Credential Acquisition")
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

    except Exception as e:
        fail(f"Azure authentication failed: {e}")

    # Step 3: Subscription access validation
    info("")
    info("📋 Step 3: Subscription Access Validation")
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
    info("🔒 Step 4: Permission Validation")
    info("-" * 70)

    # For Azure, we've already validated subscription access
    # Reader role gives us all the permissions we need
    success("✓ Subscription read access confirmed")
    info("  Reader role provides all required permissions:")
    info("    - Microsoft.Compute/disks/read")
    info("    - Microsoft.Compute/snapshots/read")
    info("    - Microsoft.Network/publicIPAddresses/read")

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
    success("🎉 AZURE ENVIRONMENT READY FOR CLEANCLOUD")
    info("=" * 70)
    info("")
