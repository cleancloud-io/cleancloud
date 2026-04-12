"""Detect dangling Docker images (untagged, unreferenced)."""

from datetime import datetime, timezone
from typing import List

import docker

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_dangling_images(
    client: docker.DockerClient,
) -> List[Finding]:
    """
    Find dangling Docker images — images with no tag and no container reference.

    Dangling images are leftover build layers from previous builds or pulls.
    They consume disk space with no functional purpose.

    Confidence: HIGH — dangling images are definitively unused.

    Permissions:
    - Docker socket read access
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    try:
        images = client.images.list(filters={"dangling": True})
    except docker.errors.APIError as e:
        raise PermissionError(f"Missing Docker API access: {e}") from e

    for image in images:
        attrs = image.attrs
        size_bytes = attrs.get("Size", 0)
        size_mb = round(size_bytes / (1024 * 1024), 1)

        created = attrs.get("Created", "")
        image_id = image.short_id.replace("sha256:", "")

        evidence = Evidence(
            signals_used=[
                "Image has no tags (dangling)",
                "Image is not referenced by any container",
                f"Image size: {size_mb} MB",
            ],
            signals_not_checked=[
                "Build cache dependencies",
                "Multi-stage build intermediate layers",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="docker",
                rule_id="docker.image.dangling",
                resource_type="docker.image",
                resource_id=image_id,
                region=None,
                title="Dangling image (no tags)",
                summary=f"Untagged image {image_id} consuming {size_mb} MB",
                reason="Image has no tags and is not referenced by any container",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details={
                    "image_id": image.id,
                    "size_mb": size_mb,
                    "created": created,
                },
            )
        )

    return findings
