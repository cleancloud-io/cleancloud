"""Detect running containers without a configured healthcheck."""

from datetime import datetime, timezone
from typing import List

import docker

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_containers_no_healthcheck(
    client: docker.DockerClient,
) -> List[Finding]:
    """
    Find running containers that have no Docker HEALTHCHECK configured.

    Containers without healthchecks can silently fail — the process stays
    running but stops serving requests. Docker and orchestrators cannot
    detect or restart unhealthy containers without this signal.

    Only running containers are checked (stopped containers are irrelevant).

    Confidence: HIGH — absence of healthcheck is deterministic.

    Permissions:
    - Docker socket read access
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    try:
        containers = client.containers.list(filters={"status": "running"})
    except docker.errors.APIError as e:
        raise PermissionError(f"Missing Docker API access: {e}") from e

    for container in containers:
        attrs = container.attrs
        config = attrs.get("Config", {})
        healthcheck = config.get("Healthcheck")

        # Healthcheck exists and is not disabled
        if healthcheck and healthcheck.get("Test", ["NONE"])[0] != "NONE":
            continue

        image = config.get("Image", "unknown")
        name = container.name

        evidence = Evidence(
            signals_used=[
                "Container is running with no HEALTHCHECK defined",
                "Docker cannot detect silent failures in this container",
            ],
            signals_not_checked=[
                "External health monitoring (Uptime Kuma, etc.)",
                "Application-level health endpoints",
                "Orchestrator-level probes (Kubernetes, Swarm)",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="docker",
                rule_id="docker.container.no_healthcheck",
                resource_type="docker.container",
                resource_id=container.short_id,
                region=None,
                title="Running container without healthcheck",
                summary=f"Container '{name}' has no HEALTHCHECK — silent failures undetected",
                reason="No Docker HEALTHCHECK configured on a running container",
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details={
                    "container_name": name,
                    "container_id": container.id,
                    "image": image,
                    "status": container.status,
                },
            )
        )

    return findings
