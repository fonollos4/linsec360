import time
import json
from repositories.deployment_repository import DeploymentRepository
from repositories.host_repository import HostRepository
from repositories.stats_repository import StatsRepository


class EventService:
    @staticmethod
    def get_event_stream():
        last_job_statuses = {}
        last_snapshot = 0
        initialized = False
        while True:
            time.sleep(1)
            jobs = DeploymentRepository.list_recent()
            if not initialized:
                last_job_statuses = {
                    job["job_id"]: job["status"] for job in jobs
                }
                initialized = True
            else:
                for job in reversed(jobs):
                    previous_status = last_job_statuses.get(job["job_id"])
                    if previous_status != job["status"]:
                        last_job_statuses[job["job_id"]] = job["status"]
                        message = (
                            f"Déploiement de {job['playbook']} démarré"
                            if job["status"] in {"queued", "running"}
                            else (
                                f"Déploiement de {job['playbook']} terminé avec succès"
                                if job["status"] == "succeeded"
                                else f"Échec du déploiement de {job['playbook']}"
                            )
                        )
                        yield EventService._encode({
                            "type": "deployment",
                            "job_id": job["job_id"],
                            "message": message,
                            "status": job["status"],
                        })

            if time.monotonic() - last_snapshot >= 5:
                stats = StatsRepository.get_latest()
                hosts = HostRepository.list_all()
                yield EventService._encode({
                    "type": "stats",
                    "data": dict(stats) if stats else {},
                })
                yield EventService._encode({
                    "type": "hosts",
                    "data": [dict(host) for host in hosts],
                })
                last_snapshot = time.monotonic()

    @staticmethod
    def _encode(payload):
        return f"data: {json.dumps(payload)}\n\n"
