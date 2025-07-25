from flask import render_template, request, jsonify, Response
from database import DatabaseManager
from services.deployment_service import DeploymentService
from services.event_service import EventService
from services.inventory_service import InventoryService
from services.playbook_service import PlaybookService
from services.validation_service import ValidationService


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
        return Response(EventService.get_event_stream(), mimetype='text/event-stream')
    
    # === ROUTES FOR HOSTS ===
    
    @app.route('/hosts')
    def list_hosts():
        """Lister tous les hôtes"""
        hosts = DatabaseManager.get_all_hosts()
        return jsonify([dict(host) for host in hosts])
    
    @app.route('/add-host', methods=['POST'])
    def add_host():
        """Add a new host"""
        try:
            host_data = {
                'name': request.form['hostname'],
                'ip': request.form['ip'], 
                'environment': request.form['environment'],
                'security_level': request.form['security-level'],
                'groups': ','.join(request.form.getlist('groups')),
                'status': 'pending'
            }
            
            # IP validation
            if not ValidationService.validate_ip(host_data['ip']):
                return jsonify({
                    'status': 'error',
                    'message': 'Adresse IP invalide'
                }), 400
            
            # Add to database
            DatabaseManager.add_host(host_data)
            
            # Update statistics
            DatabaseManager.update_stats()
        
            # Save into the inventory
            InventoryService.save_host_to_inventory(host_data)
            
            return jsonify({
                'status': 'success',
                'message': f"Hôte {host_data['name']} ajouté avec succès!"
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f"Erreur: {str(e)}"
            }), 500
    
    @app.route('/host/<int:host_id>', methods=['DELETE'])
    def delete_host(host_id):
        """Delete an host"""
        try:
            # Delete host from database
            host_data = DatabaseManager.delete_host(host_id)
            if not host_data:
                return jsonify({'status': 'error', 'message': 'Hôte non trouvé'}), 404
            
            # Update statistics
            DatabaseManager.update_stats()
            
            # Remove from inventory
            InventoryService.remove_host_from_inventory(host_data)
            
            return jsonify({
                'status': 'success',
                'message': f"Hôte {host_data['name']} supprimé avec succès!"
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f"Erreur lors de la suppression: {str(e)}"
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
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
    
    @app.route('/playbooks', methods=['POST'])
    def add_playbook():
        """Add a new playbook"""
        try:
            data = request.json
            filename = data.get('filename')
            content = data.get('content', '')
            
            PlaybookService.create_playbook(filename, content)
            
            return jsonify({
                "status": "success", 
                "message": f"Playbook {filename} créé."
            })
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    @app.route('/playbooks/<playbook_name>', methods=['PUT'])
    def edit_playbook(playbook_name):
        """Edit an existing playbook"""
        try:
            data = request.json
            content = data.get('content', '')
            
            PlaybookService.update_playbook(playbook_name, content)
            
            return jsonify({
                "status": "success", 
                "message": f"Playbook {playbook_name} mis à jour."
            })
        except ValueError as e:
            return jsonify({"status": "error", "message": str(e)}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
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
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    # === ROUTES FOR DEPLOYMENTS ===
    
    @app.route('/deploy', methods=['POST'])
    def deploy():
        """Deploy a playbook on hosts"""
        try:
            data = request.json
            environment = data.get('environment', 'production')
            playbook = data.get('playbook', 'site.yml')
            target_hosts = data.get('hosts', [])
            target_group = data.get('group', None)
            
            # Determine the target hosts
            target_hosts = DeploymentService.get_target_hosts(
                environment, target_hosts, target_group
            )
            
            # Start the deployment
            DeploymentService.start_deployment(environment, playbook, target_hosts)
            
            return jsonify({
                'status': 'success',
                'message': f"Déploiement de {playbook} sur {len(target_hosts)} hôte(s) démarré!"
            })
        except ValueError as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 400
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f"Échec du déploiement: {str(e)}"
            }), 500
    
    # === ROUTES FOR STATISTICS ===
    
    @app.route('/stats')
    def get_stats():
        """Get realtime statistics"""
        stats = DatabaseManager.get_latest_stats()
        return jsonify(dict(stats)) if stats else jsonify({})