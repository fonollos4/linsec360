import time
import json
from database import DatabaseManager

class EventService:
    EVENT_LISTENERS = []

    @staticmethod
    def get_event_stream():
        while True:
            if EventService.EVENT_LISTENERS:
                time.sleep(1)
                stats = DatabaseManager.get_latest_stats()
                hosts = DatabaseManager.get_all_hosts()

                yield f"data: {json.dumps({'type': 'stats', 'data': dict(stats) if stats else {}})}\n\n"
                yield f"data: {json.dumps({'type': 'hosts', 'data': [dict(h) for h in hosts]})}\n\n"
            else:
                time.sleep(5)

    @staticmethod
    def notify_deployment_start(environment, playbook, hosts):
        EventService.EVENT_LISTENERS.append({
            'type': 'deployment',
            'message': f"Déploiement de {playbook} sur {len(hosts)} hôte(s) démarré",
            'status': 'deploying',
            'hosts': hosts
        })

    @staticmethod
    def notify_deployment_complete(environment, playbook, hosts, success):
        status = 'secured' if success else 'error'
        message = (
            f"Déploiement de {playbook} terminé avec succès sur {len(hosts)} hôte(s)"
            if success else
            f"Échec du déploiement de {playbook} sur {len(hosts)} hôte(s)"
        )
        EventService.EVENT_LISTENERS.append({
            'type': 'deployment',
            'message': message,
            'status': status,
            'hosts': hosts
        })
