"""Detect stopped Docker containers consuming disk space."""

from datetime import datetime, timezone
from typing import List, Optional

import docker

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def _parse_docker_time(time_str: str) -> Optional[datetime]:
    """Parse Docker timestamp to datetime."""
    if not time_str:
        return None
    try:
        # Docker uses ISO 8601 with nanoseconds
        clean = time_str.split(".")[0] + "+00:00"
        return datetime.fromisoformat(clean)
    except (ValueError, AttributeError):
        return None


def find_stopped_containers(
    client: docker.DockerClient,
    min_age_days: int = 7,
) -> List[Finding]:
    """
    Find containers that have been stopped for a prolonged period.

    Stopped containers consume disk space for their writable layer and logs.
    Containers stopped for more than min_age_days are flagged.

    Confidence:
    - HIGH: Stopped for >= 2x min_age_days
    - MEDIUM: Stopped for >= min_age_days

    Permissions:
    - Docker socket read access
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    try:
        containers = client.containers.list(all=True, filters={"status": "exited"})
    except docker.errors.APIError as e:
        raise PermissionError(f"Missing Docker API access: {e}") from e

    for container in containers:
        attrs = container.attrs
        state = attrs.get("State", {})
        finished_at = _parse_docker_time(state.get("FinishedAt", ""))

        if not finished_at or finished_at.year < 2000:
            continue

        age_days = (now - finished_at).days

        if age_days < min_age_days:
            continue

        if age_days >= min_age_days * 2:
            confidence = ConfidenceLevel.HIGH
        else:
            confidence = ConfidenceLevel.MEDIUM

        image = attrs.get("Config", {}).get("Image", "unknown")
        name = container.name

        # Estimate disk from container size (writable layer)
        size_bytes = attrs.get("SizeRw", 0) or 0
        size_mb = round(size_bytes / (1024 * 1024), 1)

        evidence = Evidence(
            signals_used=[
                f"Container exited {age_days} days ago",
                f"Container status: exited (exit code {state.get('ExitCode', 'unknown')})",
                f"Writable layer size: {size_mb} MB",
            ],
            signals_not_checked=[
                "Container data volume dependencies",
                "Scheduled restart or maintenance intent",
                "Linked container dependencies",
            ],
            time_window=f"{age_days} days since exit",
        )

        findings.append(
            Finding(
                provider="docker",
                rule_id="docker.container.stopped",
                resource_type="docker.container",
                resource_id=container.short_id,
                region=None,
                title=f"Stopped container ({age_days} days)",
                summary=f"Container '{name}' has been stopped for {age_days} days",
                reason=f"Container exited {age_days} days ago and is consuming disk space",
                risk=RiskLevel.LOW,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                details={
                    "container_name": name,
                    "container_id": container.id,
                    "image": image,
                    "exit_code": state.get("ExitCode"),
                    "finished_at": finished_at.isoformat(),
                    "age_days": age_days,
                    "writable_layer_mb": size_mb,
                },
            )
        )

    return findings
