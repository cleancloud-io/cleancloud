import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied
from google.cloud import compute_v1

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Persistent disk storage cost for stopped VMs — conservative pd-standard rate.
# vCPU and RAM do not bill when TERMINATED; only attached disks continue to charge.
_DISK_COST_PER_GB_MONTH = 0.04  # pd-standard, us-central1


def _parse_gcp_timestamp(ts: str) -> Optional[datetime]:
    """Parse a GCP RFC3339 timestamp like '2024-01-15T10:30:00.000-07:00' or '...Z'."""
    if not ts:
        return None
    try:
        # Strip fractional seconds for uniform parsing across Python 3.10+
        cleaned = re.sub(r"\.\d+", "", ts)
        cleaned = cleaned.replace("Z", "+00:00")
        return datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S%z")
    except Exception:
        return None


def find_stopped_vms(
    *,
    project_id: str,
    credentials,
    region_filter: Optional[str] = None,
    max_age_days: int = 30,
) -> List[Finding]:
    """
    Find Compute Engine VMs in TERMINATED state for 30+ days.

    GCE VMs in TERMINATED status stop billing for vCPU and RAM, but attached
    persistent disks continue to incur storage charges. Long-running TERMINATED
    instances are a reliable signal of abandoned dev/staging environments or
    forgotten manual shutdowns.

    Detection logic:
    - Instance status == TERMINATED
    - lastStopTimestamp is older than `max_age_days` days
    - Cost estimated from sum of attached disk sizes (pd-standard rate)

    IAM permissions required:
    - compute.instances.list (included in roles/compute.viewer)
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)

    instances_client = compute_v1.InstancesClient(credentials=credentials)

    # aggregated_list() returns a lazy pager — PermissionDenied fires during
    # iteration (not at call time), so the try/except must wrap the full loop.
    try:
        for zone_scope, zone_instances in instances_client.aggregated_list(project=project_id):
            if not zone_instances.instances:
                continue

            zone_name = zone_scope.split("/")[-1]
            region = zone_name.rsplit("-", 1)[0]  # "us-central1-a" → "us-central1"

            if region_filter and region != region_filter:
                continue

            for instance in zone_instances.instances:
                if instance.status != "TERMINATED":
                    continue

                stop_time = _parse_gcp_timestamp(instance.last_stop_timestamp or "")

                if stop_time is None:
                    # Cannot determine stop time — flag at MEDIUM confidence
                    confidence = ConfidenceLevel.MEDIUM
                    days_stopped_actual = None
                    stop_time_str = "unknown"
                else:
                    if stop_time > cutoff:
                        continue  # Stopped recently — below threshold
                    days_stopped_actual = (now - stop_time).days
                    stop_time_str = stop_time.isoformat()
                    # 90+ days stopped is a strong abandonment signal;
                    # 30–89 days may still be a deliberate seasonal or sprint shutdown.
                    confidence = (
                        ConfidenceLevel.HIGH
                        if days_stopped_actual >= 90
                        else ConfidenceLevel.MEDIUM
                    )

                # Sum attached persistent disk sizes for cost estimate
                disks = instance.disks or []
                persistent_disks = [d for d in disks if d.type_ == "PERSISTENT"]
                total_disk_gb = sum(int(d.disk_size_gb or 0) for d in persistent_disks)
                monthly_cost = round(total_disk_gb * _DISK_COST_PER_GB_MONTH, 2)

                # Boot disk presence is the strongest signal of an abandoned environment
                boot_disk_count = sum(1 for d in disks if getattr(d, "boot", False))

                labels = dict(instance.labels) if instance.labels else {}
                machine_type_url = instance.machine_type or ""
                machine_type = machine_type_url.split("/")[-1] if machine_type_url else "unknown"

                # scheduling.automaticRestart=False → VM was configured to not restart on
                # failure (preemptible-style or intentional); mild signal of deliberate shutdown.
                scheduling = instance.scheduling
                automatic_restart = (
                    getattr(scheduling, "automatic_restart", True) if scheduling else True
                )

                last_start_ts = instance.last_start_timestamp or None

                signals = [
                    "Instance status: TERMINATED",
                    f"Attached disks: {len(persistent_disks)} persistent disk(s), {total_disk_gb} GB total",
                    f"Estimated disk cost: ~${monthly_cost}/month (pd-standard rate — see caveats)",
                ]
                if days_stopped_actual is not None:
                    signals.insert(
                        1, f"Stopped for {days_stopped_actual} days (since {stop_time_str})"
                    )
                else:
                    signals.insert(1, "Stop timestamp unavailable — confidence reduced to MEDIUM")
                if boot_disk_count > 0:
                    signals.append(
                        f"Boot disk present ({boot_disk_count} boot disk(s)) — "
                        f"strong indicator of an abandoned environment"
                    )

                if days_stopped_actual is not None:
                    duration_desc = f"has been TERMINATED for {days_stopped_actual} days"
                else:
                    duration_desc = "is TERMINATED (duration unknown)"

                details = {
                    "instance_name": instance.name,
                    "machine_type": machine_type,
                    "zone": zone_name,
                    "total_disk_gb": total_disk_gb,
                    "boot_disk_count": boot_disk_count,
                    "days_stopped_threshold": max_age_days,
                    "stop_time": stop_time_str,
                    "automatic_restart": automatic_restart,
                    "labels": labels,
                }
                if days_stopped_actual is not None:
                    details["days_stopped"] = days_stopped_actual
                if last_start_ts:
                    details["last_start_timestamp"] = last_start_ts

                findings.append(
                    Finding(
                        provider="gcp",
                        rule_id="gcp.compute.vm.stopped",
                        resource_type="gcp.compute.instance",
                        resource_id=f"projects/{project_id}/zones/{zone_name}/instances/{instance.name}",
                        region=region,
                        title=(
                            f"Stopped VM ({days_stopped_actual} Days)"
                            if days_stopped_actual is not None
                            else "Stopped VM (Duration Unknown)"
                        ),
                        summary=(
                            f"VM '{instance.name}' ({machine_type}) in zone '{zone_name}' "
                            f"{duration_desc}. "
                            f"Attached disks ({len(persistent_disks)} disk(s), {total_disk_gb} GB) "
                            f"continue billing at ~${monthly_cost}/month."
                        ),
                        reason=(
                            f"VM has been in TERMINATED state for {days_stopped_actual} days"
                            if days_stopped_actual is not None
                            else "VM is in TERMINATED state (stop timestamp unavailable)"
                        ),
                        risk=RiskLevel.MEDIUM,
                        confidence=confidence,
                        detected_at=now,
                        evidence=Evidence(
                            signals_used=signals,
                            signals_not_checked=[
                                "Planned seasonal or scheduled shutdown",
                                "IaC-managed environment pending recreation",
                                "Data preserved intentionally for forensics",
                                "Disk types (pd-ssd, pd-balanced, hyperdisk) may have higher "
                                "costs — estimate uses pd-standard baseline ($0.04/GB/month)",
                                "Regional disks (replicated across zones) incur higher storage "
                                "cost than the pd-standard estimate",
                            ],
                            time_window=f"{max_age_days} days",
                        ),
                        details=details,
                        estimated_monthly_cost_usd=monthly_cost if monthly_cost > 0 else None,
                    )
                )

    except (PermissionDenied, Forbidden) as e:
        raise PermissionError(
            f"compute.instances.list permission required (roles/compute.viewer): "
            f"{getattr(e, 'message', str(e))}"
        ) from e
    except NotFound:
        # Compute Engine API not enabled for this project — return empty
        return findings

    return findings


find_stopped_vms.RULE_ID = "gcp.compute.vm.stopped"
