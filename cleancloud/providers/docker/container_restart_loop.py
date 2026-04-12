"""Detect containers stuck in a restart loop."""

from datetime import datetime, timezone
from typing import List

import docker

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_restart_loop_containers(
    client: docker.DockerClient,
    min_restart_count: int = 5,
) -> List[Finding]:
    """
    Find containers that are stuck in a restart loop.

    Containers with restart policies (unless-stopped, always) can enter
    infinite crash-restart cycles, consuming CPU and disk (logs) without
    providing any service.

    Confidence:
    - HIGH: >= 3x min_restart_count restarts
    - MEDIUM: >= min_restart_count restarts

    Permissions:
    - Docker socket read access
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    try:
        containers = client.containers.list(all=True)
    except docker.errors.APIError as e:
        raise PermissionError(f"Missing Docker API access: {e}") from e

    for container in containers:
        attrs = container.attrs
        restart_count = attrs.get("RestartCount", 0)

        if restart_count < min_restart_count:
            continue

        state = attrs.get("State", {})
        config = attrs.get("Config", {})
        host_config = attrs.get("HostConfig", {})
        restart_policy = host_config.get("RestartPolicy", {}).get("Name", "no")
        image = config.get("Image", "unknown")
        name = container.name

        if restart_count >= min_restart_count * 3:
            confidence = ConfidenceLevel.HIGH
            risk = RiskLevel.HIGH
        else:
            confidence = ConfidenceLevel.MEDIUM
            risk = RiskLevel.MEDIUM

        evidence = Evidence(
            signals_used=[
                f"Container has restarted {restart_count} times",
                f"Restart policy: {restart_policy}",
                f"Current status: {container.status}",
            ],
            signals_not_checked=[
                "Application-specific crash causes",
                "Resource limits (OOM kills)",
                "Dependency service availability",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="docker",
                rule_id="docker.container.restart_loop",
                resource_type="docker.container",
                resource_id=container.short_id,
                region=None,
                title=f"Container restart loop ({restart_count} restarts)",
                summary=f"Container '{name}' has restarted {restart_count} times",
                reason=f"Container has restarted {restart_count} times, indicating a crash loop",
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=evidence,
                details={
                    "container_name": name,
                    "container_id": container.id,
                    "image": image,
                    "restart_count": restart_count,
                    "restart_policy": restart_policy,
                    "status": container.status,
                    "exit_code": state.get("ExitCode"),
                },
            )
        )

    return findings
