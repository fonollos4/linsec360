import os
import yaml
import subprocess
import threading
from datetime import datetime
from flask import current_app
from config import Config
from database import DatabaseManager
from services.event_service import EventService
from app import create_app

class DeploymentService:
    @staticmethod
    def get_target_hosts(environment, target_hosts=None, target_group=None):
        if target_group:
            hosts = DatabaseManager.get_hosts_by_group(target_group, environment)
            return [host['name'] for host in hosts]
        elif target_hosts:
            return target_hosts
        else:
            hosts = DatabaseManager.get_hosts_by_environment(environment)
            return [host['name'] for host in hosts]

    @staticmethod
    def start_deployment(environment, playbook, target_hosts):
        playbook_path = Config.get_playbook_path(playbook)
        if not os.path.isfile(playbook_path):
            raise ValueError(f"Le playbook {playbook} n'existe pas")

        if not target_hosts:
            raise ValueError('Aucun hôte à déployer')

        DatabaseManager.update_hosts_status(target_hosts, 'deploying')
        EventService.notify_deployment_start(environment, playbook, target_hosts)
   
        app = create_app()
        with app.app_context():
            threading.Thread(
                target=DeploymentService._run_ansible_deployment,
                args=(environment, playbook, target_hosts)
            ).start()

    @staticmethod
    def _run_ansible_deployment(environment, playbook, target_hosts):
        try:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            log_file = os.path.join(Config.LOG_DIR, f"deploy-{environment}-{playbook}-{timestamp}.log")
            env_file = os.path.join(Config.LOG_DIR, f"env-{timestamp}.yml")
            hosts_file = os.path.join(Config.LOG_DIR, f"hosts-{timestamp}.yml")

            with open(env_file, 'w') as f:
                yaml.safe_dump({'linsec_env': environment}, f)
            with open(hosts_file, 'w') as f:
                yaml.safe_dump({'target_hosts': target_hosts}, f)

            cmd = [
                "ansible-playbook",
                "-i", Config.get_inventory_path(environment),
                Config.get_playbook_path(playbook),
                "--extra-vars", f"@{env_file}",
                "--extra-vars", f"@{hosts_file}"
            ]

            with open(log_file, 'w') as log:
                log.write(f"Démarrage du déploiement à {datetime.now()}\n")
                log.write(f"Commande: {' '.join(cmd)}\n\n")
                log.flush()

                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        cwd=Config.ANSIBLE_DIR,
                        text=True
                    )
                    process.wait()

                    log.write(f"\n\nDéploiement terminé à {datetime.now()}")
                    log.write(f"\nCode de sortie: {process.returncode}")

                    if process.returncode == 0:
                        DatabaseManager.update_hosts_status(target_hosts, 'secured')
                        success = True
                    else:
                        DatabaseManager.update_hosts_status(target_hosts, 'error')
                        success = False

                    EventService.notify_deployment_complete(environment, playbook, target_hosts, success)

                except Exception as e:
                    log.write(f"\n\nERREUR: {str(e)}")
                    DatabaseManager.update_hosts_status(target_hosts, 'error')
                    EventService.notify_deployment_complete(environment, playbook, target_hosts, False)
                    raise
                finally:
                    for f in [env_file, hosts_file]:
                        try:
                            os.remove(f)
                        except:
                            pass

            DatabaseManager.update_stats()

        except Exception as e:
            current_app.logger.error(f"Erreur de déploiement: {str(e)}")
