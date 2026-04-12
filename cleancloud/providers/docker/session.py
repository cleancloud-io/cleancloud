"""Docker client session management for CleanCloud Docker provider."""

from typing import Optional

import docker
from docker.errors import DockerException


def create_docker_session(host: Optional[str] = None) -> docker.DockerClient:
    """Create a Docker client session.

    Args:
        host: Docker daemon URL (e.g. 'tcp://localhost:2375' or 'unix:///var/run/docker.sock').
              If None, uses the default socket from environment or /var/run/docker.sock.

    Returns:
        docker.DockerClient connected to the Docker daemon.

    Raises:
        EnvironmentError: If Docker daemon is not reachable.
    """
    try:
        if host:
            client = docker.DockerClient(base_url=host)
        else:
            client = docker.from_env()
        # Verify connection
        client.ping()
        return client
    except DockerException as e:
        raise EnvironmentError(
            f"Cannot connect to Docker daemon: {e}. "
            "Is Docker running? Check DOCKER_HOST or /var/run/docker.sock."
        ) from e
