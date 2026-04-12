"""Detect orphaned Docker networks with no connected containers."""

from datetime import datetime, timezone
from typing import List

import docker

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Built-in networks that should never be flagged
_BUILTIN_NETWORKS = {"bridge", "host", "none"}


def find_orphaned_networks(
    client: docker.DockerClient,
) -> List[Finding]:
    """
    Find user-created Docker networks with no connected containers.

    Orphaned networks clutter the network namespace and can cause
    IP range conflicts when new networks are created.

    Built-in networks (bridge, host, none) are excluded.

    Confidence: HIGH — zero connected containers is deterministic.

    Permissions:
    - Docker socket read access
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    try:
        networks = client.networks.list()
    except docker.errors.APIError as e:
        raise PermissionError(f"Missing Docker API access: {e}") from e

    for network in networks:
        if network.name in _BUILTIN_NETWORKS:
            continue

        attrs = network.attrs
        containers = attrs.get("Containers") or {}

        if len(containers) > 0:
            continue

        driver = attrs.get("Driver", "unknown")
        scope = attrs.get("Scope", "local")
        ipam = attrs.get("IPAM", {})
        subnet = ""
        if ipam.get("Config"):
            subnet = ipam["Config"][0].get("Subnet", "")

        evidence = Evidence(
            signals_used=[
                "Network has zero connected containers",
                "Network is user-created (not built-in)",
                f"Driver: {driver}, Scope: {scope}",
            ],
            signals_not_checked=[
                "Scheduled container attachments",
                "Docker Compose project membership",
                "Swarm service dependencies",
            ],
            time_window=None,
        )

        findings.append(
            Finding(
                provider="docker",
                rule_id="docker.network.orphaned",
                resource_type="docker.network",
                resource_id=network.short_id,
                region=None,
                title="Orphaned Docker network",
                summary=f"Network '{network.name}' has no connected containers",
                reason="User-created network with zero container connections",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details={
                    "network_name": network.name,
                    "network_id": network.id,
                    "driver": driver,
                    "scope": scope,
                    "subnet": subnet,
                    "labels": attrs.get("Labels") or {},
                },
            )
        )

    return findings
