import os
from typing import List, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient


class AzureSession:
    """
    Represents an authenticated Azure session.

    Attributes:
        credential: Azure credential object for API calls
        default_subscription_id: Optional subscription ID to scan
    """

    def __init__(
        self,
        credential,
        default_subscription_id: Optional[str] = None,
    ):
        self.credential = credential
        self.default_subscription_id = default_subscription_id

    def list_subscription_ids(self) -> List[str]:
        """
        List all accessible Azure subscription IDs for this credential.
        If default_subscription_id is provided, return only that.
        """
        if self.default_subscription_id:
            return [self.default_subscription_id]

        sub_client = SubscriptionClient(self.credential)
        subscriptions = sub_client.subscriptions.list()

        return [sub.subscription_id for sub in subscriptions]


def create_azure_session(
    subscription_id: Optional[str] = None,
) -> AzureSession:
    """
    Authenticate to Azure using DefaultAzureCredential.

    Supported authentication methods (in order):
      1. GitHub Actions OIDC (Workload Identity Federation)
      2. Azure CLI login (az login)
      3. Managed Identity
      4. Service principal with client secret (legacy fallback)

    Optional environment variables:
      - AZURE_SUBSCRIPTION_ID (overrides subscription discovery)
    """
    try:
        credential = DefaultAzureCredential()

        # Validate credentials early so doctor fails fast with a clear error
        sub_client = SubscriptionClient(credential)
        _ = list(sub_client.subscriptions.list())

    except Exception as e:
        raise EnvironmentError(
            "Unable to authenticate with Azure using DefaultAzureCredential.\n"
            "Tried GitHub OIDC, Azure CLI, Managed Identity, and service principal credentials.\n\n"
            "If running locally, run:\n"
            "  az login\n\n"
            "If running in CI, ensure Azure OIDC (workload identity federation) is configured."
        ) from e

    # Allow subscription override via env var or CLI arg
    subscription_env = os.environ.get("AZURE_SUBSCRIPTION_ID")
    default_sub = subscription_id or subscription_env

    return AzureSession(
        credential=credential,
        default_subscription_id=default_sub,
    )
