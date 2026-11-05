import hmac
import os
import sqlite3

from flask import (
    Response,
    current_app,
    jsonify,
    render_template,
    request,
    stream_with_context,
)
from database import get_db
from services.deployment_service import DeploymentService
from services.event_service import EventService
from services.host_service import HostService
from services.playbook_service import PlaybookService
from services.stats_service import StatsService


def register_routes(app):
    """Register all app routes"""
    
    @app.route('/')
    def index():
        """Page d'accueil"""
        playbooks = PlaybookService.list_playbooks()
        return render_template('index.html', playbooks=playbooks)
    
    @app.route('/events')
    def events():
        """Flux d'événements SSE"""
        return Response(
            stream_with_context(EventService.get_event_stream()),
            mimetype='text/event-stream',
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route('/health')
    def health():
        return jsonify({"status": "ok"})

    @app.route('/ready')
    def ready():
        try:
            get_db().execute("SELECT 1 FROM hosts LIMIT 0")
        except sqlite3.Error:
            current_app.logger.exception("readiness_check_failed")
            return jsonify({"status": "not_ready", "dependency": "database"}), 503
        return jsonify({"status": "ready"})
    
    # === ROUTES FOR HOSTS ===
    
    @app.route('/hosts')
    def list_hosts():
        """Lister tous les hôtes"""
        return jsonify(HostService.list_hosts())
    
    @app.route('/add-host', methods=['POST'])
    def add_host():
        """Add a new host"""
        try:
            host_data = {
                'name': request.form.get('hostname', ''),
                'ip': request.form.get('ip', ''),
                'environment': request.form.get('environment', ''),
                'security_level': request.form.get('security-level', ''),
                'groups': ','.join(request.form.getlist('groups')),
                'status': 'pending'
            }
            HostService.create_host(host_data)
            
            return jsonify({
                'status': 'success',
                'message': f"Hôte {host_data['name']} ajouté avec succès!"
            })
        except ValueError as exc:
            return jsonify({'status': 'error', 'message': str(exc)}), 400
        except Exception:
            current_app.logger.exception("host_creation_failed")
            return jsonify({
                'status': 'error',
                'message': "Impossible de créer l'hôte"
            }), 500
    
    @app.route('/host/<int:host_id>', methods=['DELETE'])
    def delete_host(host_id):
        """Delete an host"""
        try:
            host_data = HostService.delete_host(host_id)
            
            return jsonify({
                'status': 'success',
                'message': f"Hôte {host_data['name']} supprimé avec succès!"
            })
        except ValueError as exc:
            return jsonify({'status': 'error', 'message': str(exc)}), 404
        except Exception:
            current_app.logger.exception("host_deletion_failed")
            return jsonify({
                'status': 'error',
                'message': "Impossible de supprimer l'hôte"
            }), 500
    
    # === ROUTES FOR PLAYBOOKS ===
    
    @app.route('/playbooks', methods=['GET'])
    def list_playbooks():
        """List all playbooks"""
        try:
            playbooks = PlaybookService.list_playbooks()
            return jsonify({
                "status": "success",
                "playbooks": playbooks
            })
        except Exception:
            current_app.logger.exception("playbook_listing_failed")
            return jsonify({
                "status": "error",
                "message": "Impossible de lister les playbooks",
            }), 500
    
    @app.route('/playbooks', methods=['POST'])
    def add_playbook():
        """Add a new playbook"""
        try:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                raise ValueError("Le corps de la requête doit être un objet JSON")
            filename = data.get('filename')
            content = data.get('content', '')
            
            PlaybookService.create_playbook(filename, content)
            
            return jsonify({
                "status": "success", 
                "message": f"Playbook {filename} créé."
            })
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        except Exception:
            current_app.logger.exception("playbook_creation_failed")
            return jsonify({
                "status": "error",
                "message": "Impossible de créer le playbook",
            }), 500
    
    @app.route('/playbooks/<playbook_name>', methods=['PUT'])
    def edit_playbook(playbook_name):
        """Edit an existing playbook"""
        try:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                raise ValueError("Le corps de la requête doit être un objet JSON")
            content = data.get('content', '')
            
            PlaybookService.update_playbook(playbook_name, content)
            
            return jsonify({
                "status": "success", 
                "message": f"Playbook {playbook_name} mis à jour."
            })
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        except Exception:
            current_app.logger.exception("playbook_update_failed")
            return jsonify({
                "status": "error",
                "message": "Impossible de modifier le playbook",
            }), 500
    
    @app.route('/playbooks/<playbook_name>', methods=['DELETE'])
    def delete_playbook(playbook_name):
        """Delete a playbook"""
        try:
            PlaybookService.delete_playbook(playbook_name)
            
            return jsonify({
                "status": "success", 
                "message": f"Playbook {playbook_name} supprimé."
            })
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        except Exception:
            current_app.logger.exception("playbook_deletion_failed")
            return jsonify({
                "status": "error",
                "message": "Impossible de supprimer le playbook",
            }), 500
    
    # === ROUTES FOR DEPLOYMENTS ===
    
    @app.route('/deploy', methods=['POST'])
    def deploy():
        """Deploy a playbook on hosts"""
        try:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                raise ValueError("Le corps de la requête doit être un objet JSON")
            environment = data.get('environment', 'production')
            playbook = data.get('playbook', 'site.yml')
            target_hosts = data.get('hosts', [])
            target_group = data.get('group', None)
            
            # Determine the target hosts
            target_hosts = DeploymentService.get_target_hosts(
                environment, target_hosts, target_group
            )
            
            # Start the deployment
            job = DeploymentService.start_deployment(environment, playbook, target_hosts)
            
            return jsonify({
                'status': 'success',
                'job_id': job['job_id'],
                'message': f"Déploiement de {playbook} sur {len(target_hosts)} hôte(s) démarré!"
            })
        except ValueError as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 400
        except Exception:
            current_app.logger.exception("deployment_request_failed")
            return jsonify({
                'status': 'error',
                'message': "Échec du démarrage du déploiement"
            }), 500

    @app.route('/deployments')
    def list_deployments():
        return jsonify([
            _public_job(job) for job in DeploymentService.list_jobs()
        ])

    @app.route('/deployments/<job_id>')
    def get_deployment(job_id):
        job = DeploymentService.get_job(job_id)
        if not job:
            return jsonify({"status": "error", "message": "Déploiement non trouvé"}), 404
        return jsonify(_public_job(job))

    @app.route('/deployments/<job_id>/log')
    def get_deployment_log(job_id):
        configured_token = current_app.config.get("LOG_API_TOKEN")
        if not configured_token:
            return jsonify({
                "status": "error",
                "message": "Journal access is not configured",
            }), 503
        scheme, separator, supplied_token = request.headers.get(
            "Authorization",
            "",
        ).partition(" ")
        if (
            scheme != "Bearer"
            or not separator
            or not hmac.compare_digest(supplied_token, configured_token)
        ):
            return jsonify({
                "status": "error",
                "message": "Authentication required",
            }), 401

        job = DeploymentService.get_job(job_id)
        if not job:
            return jsonify({"status": "error", "message": "Déploiement non trouvé"}), 404

        log_directory = os.path.realpath(current_app.config["LOG_DIR"])
        log_path = os.path.realpath(job["log_path"])
        if os.path.commonpath((log_directory, log_path)) != log_directory:
            current_app.logger.error(
                "deployment_log_path_outside_log_directory",
                extra={"job_id": job_id},
            )
            return jsonify({"status": "error", "message": "Journal non disponible"}), 404
        try:
            with open(log_path, "rb") as log_file:
                log_file.seek(0, os.SEEK_END)
                log_size = log_file.tell()
                log_file.seek(max(0, log_size - 256 * 1024))
                content = log_file.read().decode("utf-8", errors="replace")
        except FileNotFoundError:
            return jsonify({"status": "error", "message": "Journal non disponible"}), 404
        return Response(content, mimetype="text/plain")
    
    # === ROUTES FOR STATISTICS ===
    
    @app.route('/stats')
    def get_stats():
        """Get realtime statistics"""
        return jsonify(StatsService.get_current_stats())


def _public_job(job):
    return {
        "job_id": job["job_id"],
        "environment": job["environment"],
        "playbook": job["playbook"],
        "target_hosts": job["target_hosts"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "error_message": job["error_message"],
        "log_url": f"/deployments/{job['job_id']}/log",
    }