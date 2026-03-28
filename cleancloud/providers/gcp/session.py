import os
from typing import List, Optional

import google.auth
import google.auth.exceptions
import google.auth.transport.requests
from google.cloud import resourcemanager_v3


class GcpSession:
    """
    Represents an authenticated GCP session.

    Attributes:
        credentials: Google auth credentials for API calls
        default_project_id: Optional project ID to scope scanning to a single project
    """

    def __init__(
        self,
        credentials,
        default_project_id: Optional[str] = None,
    ):
        self.credentials = credentials
        self.default_project_id = default_project_id

    def list_projects(self) -> List[dict]:
        """
        List all accessible GCP projects.
        Returns list of dicts with 'id' and 'name' keys.
        If default_project_id is set, return only that project.
        """
        client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)

        if self.default_project_id:
            project = client.get_project(name=f"projects/{self.default_project_id}")
            return [{"id": project.project_id, "name": project.display_name}]

        return [
            {"id": p.project_id, "name": p.display_name}
            for p in client.search_projects()
            if p.state == resourcemanager_v3.Project.State.ACTIVE
        ]


def create_gcp_session(
    project_id: Optional[str] = None,
) -> GcpSession:
    """
    Authenticate to GCP using Application Default Credentials (ADC).

    Supported authentication methods (in order):
      1. GOOGLE_APPLICATION_CREDENTIALS env var (service account JSON key file)
      2. gcloud auth application-default login (local development)
      3. Workload Identity Federation (GitHub Actions / OIDC)
      4. Attached service account (GCE, GKE, Cloud Run metadata server)

    Optional environment variables:
      - GOOGLE_CLOUD_PROJECT or GCLOUD_PROJECT (overrides project discovery)
    """
    try:
        credentials, detected_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        # Validate credentials early so we fail fast with a clear error
        request = google.auth.transport.requests.Request()
        credentials.refresh(request)

    except google.auth.exceptions.DefaultCredentialsError as e:
        raise EnvironmentError(
            "Unable to authenticate with GCP using Application Default Credentials.\n"
            "Tried GOOGLE_APPLICATION_CREDENTIALS, gcloud ADC, Workload Identity, "
            "and attached service account.\n\n"
            "If running locally, run:\n"
            "  gcloud auth application-default login\n\n"
            "If running in CI, ensure Workload Identity Federation is configured.\n"
            "See: https://cloud.google.com/iam/docs/workload-identity-federation"
        ) from e
    except Exception as e:
        raise EnvironmentError(
            f"GCP authentication failed: {e}\n\n"
            "If running locally, run:\n"
            "  gcloud auth application-default login"
        ) from e

    # Allow project override via CLI arg, then env vars, then ADC-detected project
    project_env = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT")
    default_project = project_id or project_env or detected_project

    return GcpSession(
        credentials=credentials,
        default_project_id=default_project,
    )
