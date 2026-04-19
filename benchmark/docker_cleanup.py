"""Graceful Docker container cleanup on process termination."""

from __future__ import annotations

import atexit
import signal
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from benchmark.logger import logger

_COMPOSE_FILE = Path(__file__).parent.parent / "scripts" / "docker-compose.yml"
_active_projects: set[tuple[str, str]] = set()
_shutdown_registered = False


def _cleanup_project(project_name: str, compose_file: str | Path) -> None:
    """Tear down a docker-compose project gracefully."""
    try:
        logger.info(f"Cleaning up Docker project: {project_name}")
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "--project-name",
                project_name,
                "down",
                "--volumes",
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            f"Timeout while cleaning up project {project_name}, forcing kill"
        )
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "--project-name",
                project_name,
                "kill",
            ],
            check=False,
            capture_output=True,
        )
    except Exception as e:
        logger.error(f"Error cleaning up project {project_name}: {e}")


def _cleanup_orphaned_containers() -> None:
    """Find and stop any orphaned containers from benchmark images."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.ID}} {{.Image}} {{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return

        benchmark_images = [
            "rufimelo/sandbox",
            "rufimelo/malicious-pr",
            "rufimelo/benign-pr",
        ]

        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(maxsplit=2)
            if len(parts) < 2:
                continue
            container_id, image = parts[0], parts[1]
            if any(pattern in image for pattern in benchmark_images):
                logger.info(
                    f"Stopping orphaned container: {image} ({container_id[:12]})"
                )
                subprocess.run(
                    ["docker", "stop", "-t", "5", container_id],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
    except Exception as e:
        logger.warning(f"Error cleaning up orphaned containers: {e}")


def _cleanup_all() -> None:
    """Clean up all tracked docker-compose projects and orphaned containers."""
    if _active_projects:
        logger.info(f"Shutting down {len(_active_projects)} Docker containers...")
        for project_name, compose_file in list(_active_projects):
            _cleanup_project(project_name, compose_file)
            _active_projects.discard((project_name, compose_file))

    _cleanup_orphaned_containers()


def _register_shutdown_handlers() -> None:
    """Register signal handlers for graceful shutdown."""
    global _shutdown_registered
    if _shutdown_registered:
        return

    def _signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        _cleanup_all()
        exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    atexit.register(_cleanup_all)
    _shutdown_registered = True


def track_project(project_name: str, compose_file: str | Path = _COMPOSE_FILE) -> None:
    """Register a docker-compose project for cleanup on shutdown."""
    _register_shutdown_handlers()
    _active_projects.add((project_name, str(compose_file)))


@contextmanager
def managed_docker_project(
    project_name: str,
    compose_file: str | Path = _COMPOSE_FILE,
) -> Generator[None, None, None]:
    """Context manager for docker-compose projects with automatic cleanup."""
    _register_shutdown_handlers()
    _active_projects.add((project_name, str(compose_file)))
    try:
        yield
    finally:
        _cleanup_project(project_name, compose_file)
        _active_projects.discard((project_name, str(compose_file)))
