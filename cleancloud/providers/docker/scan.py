"""Docker provider scanner for CleanCloud.

Scans a local or remote Docker daemon for hygiene issues:
stopped containers, dangling images, unused volumes, orphaned networks,
missing healthchecks, and restart loops.
"""

from typing import Callable, Dict, List, Optional, Tuple

import click

from cleancloud.core.finding import Finding
from cleancloud.providers.docker.rules.container_no_healthcheck import (
    find_containers_no_healthcheck,
)
from cleancloud.providers.docker.rules.container_restart_loop import (
    find_restart_loop_containers,
)
from cleancloud.providers.docker.rules.container_stopped import find_stopped_containers
from cleancloud.providers.docker.rules.image_dangling import find_dangling_images
from cleancloud.providers.docker.rules.network_orphaned import find_orphaned_networks
from cleancloud.providers.docker.rules.volume_unused import find_unused_volumes
from cleancloud.providers.docker.session import create_docker_session


# Rule map: rule_id -> function (used by policy config for enable/disable/params)
DOCKER_RULE_MAP: Dict[str, Callable] = {
    "docker.container.stopped": find_stopped_containers,
    "docker.image.dangling": find_dangling_images,
    "docker.volume.unused": find_unused_volumes,
    "docker.network.orphaned": find_orphaned_networks,
    "docker.container.no_healthcheck": find_containers_no_healthcheck,
    "docker.container.restart_loop": find_restart_loop_containers,
}

# No AI-specific rules for Docker (yet)
DOCKER_RULE_MAP_AI: Dict[str, Callable] = {}

DOCKER_RULES: List[Callable] = list(DOCKER_RULE_MAP.values())
DOCKER_AI_RULES: List[Callable] = list(DOCKER_RULE_MAP_AI.values())


def scan_docker(
    host: Optional[str] = None,
    rules: Optional[List[Callable]] = None,
) -> Tuple[List[Finding], List[dict]]:
    """
    Scan a Docker daemon for hygiene issues.

    Args:
        host: Docker daemon URL. None = default socket.
        rules: List of rule functions to run. None = all rules.

    Returns:
        (findings, skipped_rules)
    """
    if rules is None:
        rules = list(DOCKER_RULES)

    client = create_docker_session(host)

    findings: List[Finding] = []
    skipped_rules: List[dict] = []

    info = client.info()
    server_version = info.get("ServerVersion", "unknown")
    total_containers = info.get("Containers", 0)
    total_images = info.get("Images", 0)

    click.echo(f"Docker Engine: {server_version}")
    click.echo(f"Containers: {total_containers}  |  Images: {total_images}")
    click.echo()

    for rule in rules:
        rule_name = rule.__name__
        try:
            click.echo(f"  Running {rule_name}...")
            result = rule(client=client)
            findings.extend(result)
            click.echo(f"  {rule_name}: {len(result)} finding(s)")
        except PermissionError as e:
            skipped_rules.append({
                "rule": rule_name,
                "missing_permissions": str(e),
            })
            click.echo(f"  {rule_name}: skipped (permission error)")
        except Exception as e:
            skipped_rules.append({
                "rule": rule_name,
                "missing_permissions": f"Unexpected error: {type(e).__name__}: {e}",
            })
            click.echo(f"  {rule_name}: skipped ({type(e).__name__})")

    return findings, skipped_rules
