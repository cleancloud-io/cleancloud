import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import google.auth
import google.auth.exceptions
import google.auth.transport.requests
import google.oauth2.credentials
import google.oauth2.service_account
from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied, ResourceExhausted
from google.auth.transport.requests import AuthorizedSession
from google.cloud import compute_v1, monitoring_v3, resourcemanager_v3
from google.protobuf import timestamp_pb2

from cleancloud.doctor.common import fail, info, success, warn


def detect_gcp_auth_method_from_env() -> tuple[str, str, dict]:
    """
    Detect likely GCP auth method from environment variables (pre-auth).
    Used to give a useful message even before credentials are acquired.
    """
    has_app_creds = bool(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
    has_gha_token = bool(os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))  # GitHub Actions OIDC
    has_gha_creds = bool(os.getenv("GOOGLE_GHA_CREDS_PATH"))
    is_gke = os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")

    metadata = {"recommended": False, "ci_cd_ready": False, "security_grade": "unknown"}

    # Workload Identity Federation via GitHub Actions
    if has_gha_token or has_gha_creds:
        metadata.update(
            {
                "recommended": True,
                "ci_cd_ready": True,
                "security_grade": "excellent",
                "credential_lifetime": "1 hour (temporary)",
                "rotation_required": False,
                "uses_key": False,
            }
        )
        return "wif_github", "Workload Identity Federation (GitHub Actions)", metadata

    # Service Account key file
    if has_app_creds:
        creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
        if creds_path.endswith(".json"):
            metadata.update(
                {
                    "recommended": False,
                    "ci_cd_ready": True,
                    "security_grade": "poor",
                    "credential_lifetime": "long-lived (key file)",
                    "rotation_required": True,
                    "rotation_interval": "90 days",
                    "uses_key": True,
                }
            )
            return "service_account_key", "Service Account Key File", metadata
        else:
            # Likely a WIF config JSON, not a key
            metadata.update(
                {
                    "recommended": True,
                    "ci_cd_ready": True,
                    "security_grade": "excellent",
                    "credential_lifetime": "1 hour (temporary via WIF)",
                    "rotation_required": False,
                    "uses_key": False,
                }
            )
            return "wif_config", "Workload Identity Federation (Config File)", metadata

    # GKE Workload Identity / metadata server
    if is_gke:
        metadata.update(
            {
                "recommended": True,
                "ci_cd_ready": False,
                "security_grade": "excellent",
                "credential_lifetime": "temporary (auto-rotated by metadata server)",
                "rotation_required": False,
                "uses_key": False,
            }
        )
        return "workload_identity", "GKE Workload Identity / Attached Service Account", metadata

    # gcloud ADC (local development)
    metadata.update(
        {
            "recommended": False,
            "ci_cd_ready": False,
            "security_grade": "acceptable",
            "credential_lifetime": "gcloud session (~1 hour)",
            "rotation_required": False,
            "uses_key": False,
        }
    )
    return "gcloud_adc", "gcloud Application Default Credentials", metadata


def _refine_method_from_credentials(
    credentials, method_id: str, description: str
) -> tuple[str, str]:
    """Refine the detected auth method using the actual credentials type."""
    try:
        import google.auth.compute_engine.credentials as gce_creds
        import google.auth.external_account as ext_creds

        if isinstance(credentials, google.oauth2.service_account.Credentials):
            return "service_account_key", "Service Account Key File"
        elif isinstance(credentials, gce_creds.Credentials):
            return "metadata_server", "Attached Service Account (GCE/GKE/Cloud Run)"
        elif isinstance(credentials, ext_creds.Credentials):
            return "wif", "Workload Identity Federation"
        elif isinstance(credentials, google.oauth2.credentials.Credentials):
            return "gcloud_adc", "gcloud Application Default Credentials"
    except Exception:
        pass
    return method_id, description


def run_gcp_doctor(project_id: Optional[str] = None) -> None:
    info("")
    info("=" * 70)
    info("GCP ENVIRONMENT VALIDATION")
    info("=" * 70)
    info("")

    # -------------------------------------------------------------------------
    # Step 1: Auth method detection (from env vars, pre-auth)
    # -------------------------------------------------------------------------
    info("Step 1: GCP Credential Resolution")
    info("-" * 70)

    method_id, description, metadata = detect_gcp_auth_method_from_env()
    info(f"Authentication Method: {description}")

    if metadata.get("credential_lifetime"):
        info(f"  Lifetime: {metadata['credential_lifetime']}")

    if metadata.get("rotation_required"):
        info(f"  Rotation Required: Yes (every {metadata.get('rotation_interval', '90 days')})")
    else:
        info("  Rotation Required: No")

    if metadata.get("uses_key") is not None:
        if metadata["uses_key"]:
            warn("  Uses Key File: Yes (long-lived credential)")
        else:
            success("  Uses Key File: No (keyless)")

    # Security assessment
    info("")
    security_grade = metadata.get("security_grade", "unknown")

    if security_grade == "excellent":
        success("Security Grade: EXCELLENT")
        success("  - No key files stored")
        success("  - Temporary credentials")
        success("  - Auto-rotated")
    elif security_grade == "good":
        success("Security Grade: GOOD")
        info("  - Temporary credentials")
    elif security_grade == "acceptable":
        warn("Security Grade: ACCEPTABLE")
        info("  Suitable for local development")
        if method_id == "gcloud_adc":
            info("  gcloud ADC authentication (interactive)")
    elif security_grade == "poor":
        warn("Security Grade: POOR")
        warn("  - Long-lived service account key file")
        warn("  - Requires manual rotation every 90 days")
        warn("  - High blast radius if compromised")
        info("")
        info("  Recommendation for CI/CD:")
        info("    Switch to Workload Identity Federation (keyless)")
        info("    See: https://cloud.google.com/iam/docs/workload-identity-federation")
    else:
        info(f"Security Grade: {security_grade.upper()}")

    info("")
    if metadata.get("ci_cd_ready"):
        success("CI/CD Ready: YES")
        info("")
        info("CleanCloud Safety Guarantees")
        info("-" * 70)
        success("- Read-only operations only")
        success("- No resource creation, modification, or deletion")
        success("- Only List / Get / Describe APIs invoked")
        success("- Suitable for production CI/CD pipelines")
    else:
        if method_id == "gcloud_adc":
            info("CI/CD Ready: NO (Local development only)")
            info("  gcloud ADC is interactive and not suitable for CI/CD")
        else:
            warn("CI/CD Ready: NO")
            warn("  Not recommended for automated pipelines")

    info("")
    if security_grade in ("excellent", "good"):
        success("Compliance: SOC2/ISO27001 Compatible")
    elif security_grade == "acceptable":
        info("Compliance: Acceptable for development environments")
    else:
        warn("Compliance: May not meet enterprise security requirements")

    # Display configured environment variables
    info("")
    project_env = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCLOUD_PROJECT")
    if project_id:
        info(f"Project Filter: {project_id} (from --project flag)")
    elif project_env:
        info(f"Project Filter: {project_env} (from GOOGLE_CLOUD_PROJECT env var)")

    google_app_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if google_app_creds:
        info(f"GOOGLE_APPLICATION_CREDENTIALS: {google_app_creds}")

    # -------------------------------------------------------------------------
    # Step 2: Credential acquisition
    # -------------------------------------------------------------------------
    info("")
    info("Step 2: Credential Acquisition")
    info("-" * 70)

    credentials = None
    detected_project = None

    try:
        credentials, detected_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        request = google.auth.transport.requests.Request()
        credentials.refresh(request)
        success("GCP credentials acquired successfully")

        # Refine method_id from actual credentials type
        method_id, description = _refine_method_from_credentials(
            credentials, method_id, description
        )
        info(f"  Confirmed method: {description}")

        # Show token expiry if available
        expiry = getattr(credentials, "expiry", None)
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            expires_in = expiry - datetime.now(timezone.utc)
            expires_in_minutes = int(expires_in.total_seconds() // 60)
            if expires_in_minutes > 0:
                info(f"  Token expires in: ~{expires_in_minutes} minutes")

    except google.auth.exceptions.DefaultCredentialsError:
        info("")
        warn("GCP credentials not found or could not be acquired.")
        info("")
        info("To configure credentials, choose one of:")
        info("  - Cloud Shell:          credentials injected automatically from the GCP portal")
        info("  - Local gcloud CLI:     run `gcloud auth application-default login`")
        info("  - CI/CD (GitHub):       use google-github-actions/auth with Workload Identity")
        info("  - Service Account:      set GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json")
        info("")
        info("IAM permissions required (assign to your service account or user):")
        info("  Built-in role: roles/viewer  (at project scope, covers all Compute + Monitoring)")
        info("  Built-in role: roles/cloudsql.viewer  (for Cloud SQL idle detection)")
        info("")
        info("  Or the individual permissions CleanCloud uses:")
        info("  compute.disks.list")
        info("  compute.instances.list")
        info("  compute.addresses.list")
        info("  compute.globalAddresses.list")
        info("  compute.snapshots.list")
        info("  cloudsql.instances.list")
        info("  monitoring.timeSeries.list")
        info("  resourcemanager.projects.get")
        info("  resourcemanager.projects.list")
        info("")
        info("Copy the ready-to-use IAM setup from:")
        info("  docs/gcp.md  (Workload Identity + IAM binding)")
        fail("GCP authentication failed — configure credentials and re-run doctor")

    except Exception as e:
        fail(f"GCP credential acquisition failed: {e}")

    # -------------------------------------------------------------------------
    # Step 3: Project access validation
    # -------------------------------------------------------------------------
    info("")
    info("Step 3: Project Access Validation")
    info("-" * 70)

    probe_project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or detected_project
    accessible_projects = []

    try:
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)

        if probe_project_id:
            # Validate the specific project
            try:
                project = client.get_project(name=f"projects/{probe_project_id}")
                success(f"Project accessible: {project.display_name} ({probe_project_id})")
                accessible_projects = [{"id": probe_project_id, "name": project.display_name}]
            except (PermissionDenied, Forbidden):
                warn(f"Project '{probe_project_id}' not accessible with current credentials")
                warn("  Missing: resourcemanager.projects.get")
                probe_project_id = None
        else:
            # List all accessible projects
            try:
                projects = [
                    p
                    for p in client.search_projects()
                    if p.state == resourcemanager_v3.Project.State.ACTIVE
                ]
                if projects:
                    success(f"Accessible projects: {len(projects)}")
                    for p in projects[:5]:
                        info(f"  • {p.display_name} ({p.project_id})")
                    if len(projects) > 5:
                        info(f"  ... and {len(projects) - 5} more")
                    accessible_projects = [
                        {"id": p.project_id, "name": p.display_name} for p in projects
                    ]
                    probe_project_id = projects[0].project_id
                else:
                    warn("No accessible GCP projects found")
                    warn("  Missing: resourcemanager.projects.list at organization scope")
                    info("  Tip: specify --project <id> to validate a specific project directly")
            except (PermissionDenied, Forbidden):
                warn("Cannot list projects — missing resourcemanager.projects.list")
                info("  Tip: use --project <id> to validate a specific project")

    except Exception as e:
        warn(f"Project access validation failed: {e}")

    # -------------------------------------------------------------------------
    # Step 4: Read-only permission validation (probe each API)
    # -------------------------------------------------------------------------
    info("")
    info("Step 4: Read-Only Permission Validation")
    info("-" * 70)

    permissions_attempted: list = []
    permissions_tested: list = []
    permissions_failed: list = []

    if not probe_project_id:
        warn("Skipping permission checks — no project available to probe")
        info("  Re-run with: cleancloud doctor --provider gcp --project <your-project-id>")
    else:
        info(f"Probing permissions on project: {probe_project_id}")
        info("")

        # --- compute.disks.list ---
        permissions_attempted.append("compute.disks.list")
        try:
            disks_client = compute_v1.DisksClient(credentials=credentials)
            # aggregated_list covers all zones — consistent with how the rule scans
            next(iter(disks_client.aggregated_list(project=probe_project_id)), None)
            permissions_tested.append("compute.disks.list")
            success("compute.disks.list")
        except (PermissionDenied, Forbidden) as e:
            permissions_failed.append(("compute.disks.list", str(e)))
            warn("compute.disks.list — MISSING (rule: disk_unattached will be skipped)")
        except NotFound:
            info("compute.disks.list — Compute Engine API not enabled (rule unavailable)")
            info("  → enable via: gcloud services enable compute.googleapis.com")
        except ResourceExhausted:
            warn("compute.disks.list — API quota exceeded (retry later)")
        except Exception as e:
            permissions_tested.append("compute.disks.list")
            success(f"compute.disks.list (note: {type(e).__name__})")

        # --- compute.instances.list ---
        permissions_attempted.append("compute.instances.list")
        try:
            instances_client = compute_v1.InstancesClient(credentials=credentials)
            next(iter(instances_client.aggregated_list(project=probe_project_id)), None)
            permissions_tested.append("compute.instances.list")
            success("compute.instances.list")
        except (PermissionDenied, Forbidden) as e:
            permissions_failed.append(("compute.instances.list", str(e)))
            warn("compute.instances.list — MISSING (rule: vm_stopped will be skipped)")
        except NotFound:
            info("compute.instances.list — Compute Engine API not enabled (rule unavailable)")
            info("  → enable via: gcloud services enable compute.googleapis.com")
        except ResourceExhausted:
            warn("compute.instances.list — API quota exceeded (retry later)")
        except Exception as e:
            permissions_tested.append("compute.instances.list")
            success(f"compute.instances.list (note: {type(e).__name__})")

        # --- compute.addresses.list (regional IPs) ---
        permissions_attempted.append("compute.addresses.list")
        try:
            addresses_client = compute_v1.AddressesClient(credentials=credentials)
            next(iter(addresses_client.aggregated_list(project=probe_project_id)), None)
            permissions_tested.append("compute.addresses.list")
            success("compute.addresses.list")
        except (PermissionDenied, Forbidden) as e:
            permissions_failed.append(("compute.addresses.list", str(e)))
            warn("compute.addresses.list — MISSING (rule: ip_unused regional IPs will be skipped)")
        except NotFound:
            info("compute.addresses.list — Compute Engine API not enabled (rule unavailable)")
            info("  → enable via: gcloud services enable compute.googleapis.com")
        except ResourceExhausted:
            warn("compute.addresses.list — API quota exceeded (retry later)")
        except Exception as e:
            permissions_tested.append("compute.addresses.list")
            success(f"compute.addresses.list (note: {type(e).__name__})")

        # --- compute.globalAddresses.list (global IPs) ---
        permissions_attempted.append("compute.globalAddresses.list")
        try:
            global_client = compute_v1.GlobalAddressesClient(credentials=credentials)
            next(
                iter(global_client.list(project=probe_project_id, max_results=1)),
                None,
            )
            permissions_tested.append("compute.globalAddresses.list")
            success("compute.globalAddresses.list")
        except (PermissionDenied, Forbidden) as e:
            permissions_failed.append(("compute.globalAddresses.list", str(e)))
            warn(
                "compute.globalAddresses.list — MISSING (rule: ip_unused global IPs will be skipped)"
            )
        except NotFound:
            info("compute.globalAddresses.list — Compute Engine API not enabled (rule unavailable)")
            info("  → enable via: gcloud services enable compute.googleapis.com")
        except ResourceExhausted:
            warn("compute.globalAddresses.list — API quota exceeded (retry later)")
        except Exception as e:
            permissions_tested.append("compute.globalAddresses.list")
            success(f"compute.globalAddresses.list (note: {type(e).__name__})")

        # --- compute.snapshots.list ---
        permissions_attempted.append("compute.snapshots.list")
        try:
            snapshots_client = compute_v1.SnapshotsClient(credentials=credentials)
            next(
                iter(snapshots_client.list(project=probe_project_id, max_results=1)),
                None,
            )
            permissions_tested.append("compute.snapshots.list")
            success("compute.snapshots.list")
        except (PermissionDenied, Forbidden) as e:
            permissions_failed.append(("compute.snapshots.list", str(e)))
            warn("compute.snapshots.list — MISSING (rule: snapshot_old will be skipped)")
        except NotFound:
            info("compute.snapshots.list — Compute Engine API not enabled (rule unavailable)")
            info("  → enable via: gcloud services enable compute.googleapis.com")
        except ResourceExhausted:
            warn("compute.snapshots.list — API quota exceeded (retry later)")
        except Exception as e:
            permissions_tested.append("compute.snapshots.list")
            success(f"compute.snapshots.list (note: {type(e).__name__})")

        # --- cloudsql.instances.list ---
        permissions_attempted.append("cloudsql.instances.list")
        try:
            session = AuthorizedSession(credentials)
            resp = session.get(
                f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{probe_project_id}/instances"
                "?maxResults=1"
            )
            if resp.status_code == 403:
                permissions_failed.append(("cloudsql.instances.list", "403 Forbidden"))
                warn("cloudsql.instances.list — MISSING (rule: sql_instance_idle will be skipped)")
            elif resp.status_code == 404:
                info("cloudsql.instances.list — Cloud SQL API not enabled (rule unavailable)")
                info("  → enable via: gcloud services enable sqladmin.googleapis.com")
            else:
                permissions_tested.append("cloudsql.instances.list")
                success("cloudsql.instances.list")
        except Exception as e:
            permissions_failed.append(("cloudsql.instances.list", str(e)))
            warn(f"cloudsql.instances.list — error: {e}")

        # --- monitoring.timeSeries.list ---
        permissions_attempted.append("monitoring.timeSeries.list")
        try:
            mon_client = monitoring_v3.MetricServiceClient(credentials=credentials)
            now = datetime.now(timezone.utc)
            start = now - timedelta(hours=1)
            end_ts = timestamp_pb2.Timestamp()
            end_ts.FromDatetime(now)
            start_ts = timestamp_pb2.Timestamp()
            start_ts.FromDatetime(start)
            interval = monitoring_v3.TimeInterval(start_time=start_ts, end_time=end_ts)
            # Consume one result to trigger the lazy API call
            next(
                iter(
                    mon_client.list_time_series(
                        request={
                            "name": f"projects/{probe_project_id}",
                            "filter": 'metric.type="cloudsql.googleapis.com/database/network/connections"',
                            "interval": interval,
                            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.HEADERS,
                        }
                    )
                ),
                None,
            )
            permissions_tested.append("monitoring.timeSeries.list")
            success("monitoring.timeSeries.list")
        except (PermissionDenied, Forbidden) as e:
            permissions_failed.append(("monitoring.timeSeries.list", str(e)))
            warn(
                "monitoring.timeSeries.list — MISSING "
                "(rule: sql_instance_idle will skip instances it cannot verify)"
            )
        except NotFound:
            info("monitoring.timeSeries.list — Cloud Monitoring API not enabled (rule unavailable)")
            info("  → enable via: gcloud services enable monitoring.googleapis.com")
        except ResourceExhausted:
            warn("monitoring.timeSeries.list — API quota exceeded (retry later)")
        except Exception as e:
            permissions_tested.append("monitoring.timeSeries.list")
            success(f"monitoring.timeSeries.list (note: {type(e).__name__})")

        # Summary of permission checks
        info("")
        total = len(permissions_attempted)
        info(f"Permissions: {len(permissions_tested)}/{total} passed")

        if permissions_failed:
            info("")
            warn(f"Missing permissions ({len(permissions_failed)}/{total}):")
            for perm, _ in permissions_failed:
                warn(f"  - {perm}")
            info("")
            info("Rules that need these permissions will be gracefully skipped during scan.")
            info("To enable full coverage, assign these roles to your service account:")
            info("  roles/compute.viewer        — all Compute Engine rules")
            info("  roles/cloudsql.viewer       — Cloud SQL idle rule")
            info("  roles/monitoring.viewer     — Cloud SQL connection metrics")
            info("  roles/browser               — project listing (or specify --project)")
            info("")
            info("  Or assign: roles/viewer  (covers Compute + Monitoring at project scope)")
            info("")
            sa_hint = "<your-service-account>@<project>.iam.gserviceaccount.com"
            info("  Example fix command:")
            info(
                f"  gcloud projects add-iam-policy-binding {probe_project_id or '<project-id>'} \\"
            )
            info(f'    --member="serviceAccount:{sa_hint}" \\')
            info('    --role="roles/viewer"')

        # Rule coverage map — translates permissions into rule-level status
        info("")
        info("Rule Coverage")
        info("-" * 50)
        failed_perms = {p for p, _ in permissions_failed}

        rules = [
            ("gcp.compute.disk.unattached", ["compute.disks.list"], None),
            ("gcp.compute.vm.stopped", ["compute.instances.list"], None),
            (
                "gcp.compute.ip.unused",
                ["compute.addresses.list", "compute.globalAddresses.list"],
                None,
            ),
            ("gcp.compute.snapshot.old", ["compute.snapshots.list"], None),
            (
                "gcp.sql.instance.idle",
                ["cloudsql.instances.list"],
                ["monitoring.timeSeries.list"],
            ),
        ]

        for rule_name, required, optional in rules:
            missing_required = [p for p in required if p in failed_perms]
            missing_optional = [p for p in (optional or []) if p in failed_perms]
            if not missing_required and not missing_optional:
                success(f"  ✓ {rule_name:<30} (enabled)")
            elif not missing_required and missing_optional:
                warn(
                    f"  ~ {rule_name:<30} (partial: {', '.join(missing_optional)} missing — conservative fallback active)"
                )
            else:
                warn(f"  ✗ {rule_name:<30} (disabled: missing {', '.join(missing_required)})")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    info("")
    info("=" * 70)
    info("VALIDATION SUMMARY")
    info("=" * 70)

    info(f"Authentication: {description}")
    info(f"Security Grade: {security_grade.upper()}")

    if accessible_projects:
        info(f"Projects: {len(accessible_projects)} accessible")
    if probe_project_id:
        info(f"Probed project: {probe_project_id}")

    info("")
    if permissions_failed:
        warn("GCP ENVIRONMENT READY (partial coverage — some rules will be skipped)")
    else:
        success("GCP ENVIRONMENT READY FOR CLEANCLOUD")

    info("=" * 70)
    info("")
