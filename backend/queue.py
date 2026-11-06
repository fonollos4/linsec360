"""Job queue abstraction: in-process threads for dev, RQ for production."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from .config import get_settings

logger = logging.getLogger(__name__)


class JobQueue(Protocol):
    def enqueue_deployment(self, deployment_id: str) -> None: ...


class ThreadJobQueue:
    """Development fallback. Jobs do not survive a process restart."""

    def __init__(self, workers: int = 2):
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix="linsec-deploy",
        )

    def enqueue_deployment(self, deployment_id: str) -> None:
        from .workers.deployment_worker import run_deployment

        self._executor.submit(run_deployment, deployment_id)


class RqJobQueue:
    """Production queue backed by Redis + RQ."""

    def __init__(self, redis_url: str):
        from redis import Redis
        from rq import Queue

        self._queue = Queue(
            "deployments",
            connection=Redis.from_url(redis_url),
        )

    def enqueue_deployment(self, deployment_id: str) -> None:
        self._queue.enqueue(
            "backend.workers.deployment_worker.run_deployment",
            deployment_id,
            job_timeout="30m",
            result_ttl=86400,
            failure_ttl=86400,
        )


_queue: JobQueue | None = None


def get_queue() -> JobQueue:
    global _queue
    if _queue is None:
        settings = get_settings()
        if settings.redis_url:
            logger.info("Using RQ deployment queue")
            _queue = RqJobQueue(settings.redis_url)
        else:
            logger.info("Using in-process deployment queue")
            _queue = ThreadJobQueue(settings.deployment_worker_threads)
    return _queue


def set_queue(queue: JobQueue | None) -> None:
    """Testing/embedding hook."""
    global _queue
    _queue = queue
