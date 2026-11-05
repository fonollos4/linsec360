import json
import os
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timezone

import yaml
from flask import current_app

from config import Config
from repositories.deployment_repository import DeploymentRepository
from repositories.host_repository import HostRepository
from repositories.stats_repository import StatsRepository
from services.validation_service import ValidationService


class DeploymentService:
    @staticmethod
    def get_target_hosts(environment, target_hosts=None, target_group=None):
        if not ValidationService.validate_environment_name(environment):
            raise ValueError("Environnement invalide")

        if target_group is not None:
            if not ValidationService.validate_group_name(target_group):
                raise ValueError("Groupe invalide")
            hosts = HostRepository.get_by_group(target_group, environment)
        elif target_hosts:
            if not isinstance(target_hosts, list) or any(
                not ValidationService.validate_host_name(host)
                for host in target_hosts
            ):
                raise ValueError("Liste d'hôtes invalide")
            available_hosts = {
                host["name"] for host in HostRepository.get_by_environment(environment)
            }
            if not set(target_hosts).issubset(available_hosts):
                raise ValueError("Un ou plusieurs hôtes ne font pas partie de cet environnement")
            return list(dict.fromkeys(target_hosts))
        else:
            hosts = HostRepository.get_by_environment(environment)
        return [host["name"] for host in hosts]

    @staticmethod
    def start_deployment(environment, playbook, target_hosts):
        if not ValidationService.validate_environment_name(environment):
            raise ValueError("Environnement invalide")
        if not ValidationService.validate_playbook_name(playbook):
            raise ValueError("Nom de playbook invalide")
        if not isinstance(target_hosts, list) or any(
            not ValidationService.validate_host_name(host) for host in target_hosts
        ):
            raise ValueError("Liste d'hôtes invalide")
        target_hosts = list(dict.fromkeys(target_hosts))
        if not target_hosts:
            raise ValueError("Aucun hôte à déployer")
        available_hosts = {
            host["name"] for host in HostRepository.get_by_environment(environment)
        }
        if not set(target_hosts).issubset(available_hosts):
            raise ValueError("Un ou plusieurs hôtes ne font pas partie de cet environnement")

        playbook_path = Config.get_playbook_path(playbook)
        if not os.path.isfile(playbook_path) or os.path.islink(playbook_path):
            raise ValueError(f"Le playbook {playbook} n'existe pas")

        job_id = str(uuid.uuid4())
        log_path = os.path.join(Config.LOG_DIR, f"deploy-{job_id}.log")
        job = {
            "job_id": job_id,
            "environment": environment,
            "playbook": playbook,
            "target_hosts": list(target_hosts),
            "status": "queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "finished_at": None,
            "log_path": log_path,
            "error_message": None,
        }

        DeploymentRepository.create(job)
        HostRepository.update_statuses(target_hosts, "deploying")
        app = current_app._get_current_object()
        worker = threading.Thread(
            target=DeploymentService._run_ansible_deployment,
            args=(app, job),
            name=f"deployment-{job_id}",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError as exc:
            HostRepository.update_statuses(target_hosts, "error")
            finished_at = datetime.now(timezone.utc).isoformat()
            DeploymentRepository.update_status(
                job_id,
                "failed",
                finished_at=finished_at,
                error_message=str(exc),
            )
            raise

        DeploymentService._log_event(
            app,
            "info",
            "deployment_queued",
            job_id=job_id,
            environment=environment,
            playbook=playbook,
            target_hosts=target_hosts,
        )
        return job

    @staticmethod
    def _run_ansible_deployment(app, job):
        with app.app_context():
            started_at = datetime.now(timezone.utc).isoformat()
            try:
                DeploymentRepository.update_status(
                    job["job_id"],
                    "running",
                    started_at=started_at,
                )
            except Exception:
                DeploymentService._log_event(
                    app,
                    "exception",
                    "deployment_worker_start_failed",
                    job_id=job["job_id"],
                )
                return
            temporary_paths = []
            success = False
            error_message = None

            try:
                os.makedirs(Config.LOG_DIR, mode=0o700, exist_ok=True)
                env_path = DeploymentService._write_extra_vars(
                    {"linsec_env": job["environment"]}
                )
                temporary_paths.append(env_path)
                hosts_path = DeploymentService._write_extra_vars(
                    {"target_hosts": job["target_hosts"]}
                )
                temporary_paths.append(hosts_path)

                command = [
                    "ansible-playbook",
                    "-i",
                    Config.get_inventory_path(job["environment"]),
                    Config.get_playbook_path(job["playbook"]),
                    "--extra-vars",
                    f"@{env_path}",
                    "--extra-vars",
                    f"@{hosts_path}",
                ]

                descriptor = os.open(
                    job["log_path"],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as log:
                    log.write(
                        f"job_id={job['job_id']} environment={job['environment']} "
                        f"playbook={job['playbook']} "
                        f"hosts={','.join(job['target_hosts'])}\n"
                    )
                    log.flush()
                    process = subprocess.run(
                        command,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        cwd=Config.ANSIBLE_DIR,
                        check=False,
                        text=True,
                    )
                    log.write(
                        f"\nfinished_at={datetime.now(timezone.utc).isoformat()} "
                        f"return_code={process.returncode}\n"
                    )

                success = process.returncode == 0
                if not success:
                    error_message = (
                        f"ansible-playbook exited with code {process.returncode}"
                    )
                HostRepository.update_statuses(
                    job["target_hosts"],
                    "secured" if success else "error",
                )
                StatsRepository.refresh()
            except Exception as exc:
                success = False
                error_message = "Deployment execution failed"
                DeploymentService._log_event(
                    app,
                    "exception",
                    "deployment_failed",
                    job_id=job["job_id"],
                    environment=job["environment"],
                    playbook=job["playbook"],
                    target_hosts=job["target_hosts"],
                )
                try:
                    HostRepository.update_statuses(job["target_hosts"], "error")
                    StatsRepository.refresh()
                except Exception:
                    DeploymentService._log_event(
                        app,
                        "exception",
                        "deployment_failure_status_update_failed",
                        job_id=job["job_id"],
                    )
                try:
                    descriptor = os.open(
                        job["log_path"],
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    os.fchmod(descriptor, 0o600)
                    with os.fdopen(descriptor, "a", encoding="utf-8") as log:
                        log.write(f"\nerror={exc}\n")
                except OSError:
                    DeploymentService._log_event(
                        app,
                        "exception",
                        "deployment_log_write_failed",
                        job_id=job["job_id"],
                    )
            finally:
                for path in temporary_paths:
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        DeploymentService._log_event(
                            app,
                            "exception",
                            "deployment_temp_file_cleanup_failed",
                            job_id=job["job_id"],
                            path=path,
                        )

            try:
                DeploymentRepository.update_status(
                    job["job_id"],
                    "succeeded" if success else "failed",
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    error_message=error_message,
                )
            except Exception:
                DeploymentService._log_event(
                    app,
                    "exception",
                    "deployment_status_persistence_failed",
                    job_id=job["job_id"],
                )
            DeploymentService._log_event(
                app,
                "info",
                "deployment_finished",
                job_id=job["job_id"],
                environment=job["environment"],
                playbook=job["playbook"],
                target_hosts=job["target_hosts"],
                success=success,
            )

    @staticmethod
    def _log_event(app, level, event, **context):
        message = json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **context,
            },
            separators=(",", ":"),
        )
        if level == "exception":
            app.logger.exception(message)
        else:
            getattr(app.logger, level)(message)

    @staticmethod
    def _write_extra_vars(values):
        descriptor, path = tempfile.mkstemp(
            prefix="linsec-deploy-",
            suffix=".yml",
            dir=Config.LOG_DIR,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as extra_vars:
                yaml.safe_dump(values, extra_vars)
            return path
        except Exception:
            os.unlink(path)
            raise

    @staticmethod
    def get_job(job_id):
        return DeploymentRepository.get_by_id(job_id)

    @staticmethod
    def list_jobs():
        return DeploymentRepository.list_recent()
