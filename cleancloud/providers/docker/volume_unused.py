"""Detect unused Docker volumes not mounted by any container."""

from datetime import datetime, timezone
from typing import List

import docker

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_unused_volumes(
    client: docker.DockerClient,
) -> List[Finding]:
    """
    Find Docker volumes not mounted by any running or stopped container.

    Orphaned volumes accumulate after containers are removed without
    the -v flag. They consume disk space indefinitely.

    Confidence: HIGH — Docker API reports volumes with zero references.

    Permissions:
    - Docker socket read access
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    try:
        # Docker's dangling filter returns volumes not referenced by any container
        volumes = client.volumes.list(filters={"dangling": True})
    except docker.errors.APIError as e:
        raise PermissionError(f"Missing Docker API access: {e}") from e

    for volume in volumes:
        attrs = volume.attrs
        name = volume.name
        driver = attrs.get("Driver", "local")
        mountpoint = attrs.get("Mountpoint", "")
        created = attrs.get("CreatedAt", "")
        labels = attrs.get("Labels") or {}

        evidence = Evidence(
            signals_used=[
                "Volume is not mounted by any container (dangling)",
                f"Driver: {driver}",
            ],
            signals_not_checked=[
                "Manual mount usage outside Docker",
                "Backup or snapshot intent",
                "Data migration in progress",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="docker",
                rule_id="docker.volume.unused",
                resource_type="docker.volume",
                resource_id=name[:12] if len(name) > 12 else name,
                region=None,
                title="Unused Docker volume",
                summary=f"Volume '{name}' is not mounted by any container",
                reason="Volume has zero container references and is consuming disk space",
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details={
                    "volume_name": name,
                    "driver": driver,
                    "mountpoint": mountpoint,
                    "created": created,
                    "labels": labels,
                },
            )
        )

    return findings
