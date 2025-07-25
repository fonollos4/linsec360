import os
import sqlite3
import yaml
import subprocess
import threading
import time
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, g, Response

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('FLASK_SECRET', 'supersecretkey')

# Configuration paths
INVENTORY_DIR = "/ansible/inventories"
ANSIBLE_DIR = "/ansible"
PLAYBOOKS_DIR = os.path.join(ANSIBLE_DIR, "playbooks")
LOG_DIR = "/var/log/linsec"
DATABASE = os.path.join(app.instance_path, 'linsec.db')
EVENT_LISTENERS = []

# Configuration SQLite
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    os.makedirs(app.instance_path, exist_ok=True)
    
    db = sqlite3.connect(DATABASE)
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()

@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    print('Initialized the database.')

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

# SSE Event streaming
def event_stream():
    while True:
        if EVENT_LISTENERS:
            # Check for updates every second
            time.sleep(1)
            db = get_db()
            stats = db.execute('SELECT * FROM stats ORDER BY timestamp DESC LIMIT 1').fetchone()
            hosts = db.execute('SELECT * FROM hosts ORDER BY added_date DESC').fetchall()
            
            # Send stats update
            stats_data = {
                'type': 'stats',
                'data': dict(stats) if stats else {}
            }
            yield f"data: {json.dumps(stats_data)}\n\n"
            
            # Send hosts update
            hosts_data = {
                'type': 'hosts',
                'data': [dict(host) for host in hosts]
            }
            yield f"data: {json.dumps(hosts_data)}\n\n"
        else:
            time.sleep(5)

@app.route('/events')
def events():
    return Response(event_stream(), mimetype='text/event-stream')

def notify_deployment_start(environment, playbook, hosts):
    deployment_data = {
        'type': 'deployment',
        'message': f"Déploiement de {playbook} sur {len(hosts)} hôte(s) démarré",
        'status': 'deploying',
        'hosts': hosts
    }
    EVENT_LISTENERS.append(deployment_data)

def notify_deployment_complete(environment, playbook, hosts, success):
    status = 'secured' if success else 'error'
    message = f"Déploiement de {playbook} sur {len(hosts)} hôte(s) terminé avec succès" if success \
        else f"Échec du déploiement de {playbook} sur {len(hosts)} hôte(s)"
    
    deployment_data = {
        'type': 'deployment',
        'message': message,
        'status': status,
        'hosts': hosts
    }
    EVENT_LISTENERS.append(deployment_data)

# Routes principales
@app.route('/')
def index():
    db = get_db()
    playbooks = list_playbooks_internal()
    return render_template('index.html', playbooks=playbooks)

# --- Gestion des hôtes ---
@app.route('/add-host', methods=['POST'])
def add_host():
    try:
        host_data = {
            'name': request.form['hostname'],
            'ip': request.form['ip'],
            'environment': request.form['environment'],
            'security_level': request.form['security-level'],
            'groups': ','.join(request.form.getlist('groups')),
            'status': 'pending'
        }
        
        # Validation de l'IP
        if not validate_ip(host_data['ip']):
            return jsonify({
                'status': 'error',
                'message': 'Adresse IP invalide'
            }), 400
        
        db = get_db()
        db.execute(
            'INSERT INTO hosts (name, ip, environment, security_level, groups, status) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (host_data['name'], host_data['ip'], host_data['environment'], 
             host_data['security_level'], host_data['groups'], host_data['status'])
        )
        db.commit()
        
        # Mettre à jour les statistiques
        update_stats()
        
        # Sauvegarder dans l'inventaire Ansible
        save_host_to_inventory(host_data)
        
        return jsonify({
            'status': 'success',
            'message': f"Host {host_data['name']} added successfully!"
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Error: {str(e)}"
        }), 500

def validate_ip(ip):
    """Valide une adresse IPv4"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

# --- Gestion des playbooks ---
@app.route('/playbooks', methods=['GET'])
def list_playbooks():
    try:
        playbooks = list_playbooks_internal()
        return jsonify({
            "status": "success",
            "playbooks": playbooks
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

def list_playbooks_internal():
    """Liste les playbooks disponibles dans le répertoire"""
    os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
    files = os.listdir(PLAYBOOKS_DIR)
    return [f for f in files if f.endswith('.yml') or f.endswith('.yaml')]

@app.route('/playbooks', methods=['POST'])
def add_playbook():
    try:
        data = request.json
        filename = data.get('filename')
        content = data.get('content', '')

        if not filename or not (filename.endswith('.yml') or filename.endswith('.yaml')):
            return jsonify({"status": "error", "message": "Filename must end with .yml or .yaml"}), 400

        filepath = os.path.join(PLAYBOOKS_DIR, filename)
        if os.path.exists(filepath):
            return jsonify({"status": "error", "message": "Playbook already exists"}), 400

        with open(filepath, 'w') as f:
            f.write(content)

        return jsonify({"status": "success", "message": f"Playbook {filename} created."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/playbooks/<playbook_name>', methods=['PUT'])
def edit_playbook(playbook_name):
    try:
        if not (playbook_name.endswith('.yml') or playbook_name.endswith('.yaml')):
            return jsonify({"status": "error", "message": "Invalid playbook name"}), 400

        filepath = os.path.join(PLAYBOOKS_DIR, playbook_name)
        if not os.path.exists(filepath):
            return jsonify({"status": "error", "message": "Playbook not found"}), 404

        data = request.json
        content = data.get('content', '')
        with open(filepath, 'w') as f:
            f.write(content)

        return jsonify({"status": "success", "message": f"Playbook {playbook_name} updated."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/playbooks/<playbook_name>', methods=['DELETE'])
def delete_playbook(playbook_name):
    try:
        if not (playbook_name.endswith('.yml') or playbook_name.endswith('.yaml')):
            return jsonify({"status": "error", "message": "Invalid playbook name"}), 400

        filepath = os.path.join(PLAYBOOKS_DIR, playbook_name)
        if not os.path.exists(filepath):
            return jsonify({"status": "error", "message": "Playbook not found"}), 404

        os.remove(filepath)
        return jsonify({"status": "success", "message": f"Playbook {playbook_name} deleted."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Déploiement avec sélection de playbook et hôtes ---
@app.route('/deploy', methods=['POST'])
def deploy():
    try:
        data = request.json
        environment = data.get('environment', 'production')
        playbook = data.get('playbook', 'site.yml')
        target_hosts = data.get('hosts', [])
        target_group = data.get('group', None)

        # Valide que le playbook existe
        playbook_path = os.path.join(PLAYBOOKS_DIR, playbook)
        if not os.path.isfile(playbook_path):
            return jsonify({"status": "error", "message": f"Playbook {playbook} does not exist"}), 400

        # Déterminer les hôtes cibles
        db = get_db()
        if target_group:
            # Récupérer les hôtes du groupe
            hosts = db.execute(
                "SELECT name FROM hosts WHERE groups LIKE ? AND environment = ?",
                (f'%{target_group}%', environment)
            ).fetchall()
            target_hosts = [host['name'] for host in hosts]
        elif not target_hosts:
            # Tous les hôtes de l'environnement
            hosts = db.execute(
                "SELECT name FROM hosts WHERE environment = ?",
                (environment,)
            ).fetchall()
            target_hosts = [host['name'] for host in hosts]

        if not target_hosts:
            return jsonify({
                'status': 'error',
                'message': 'Aucun hôte à déployer'
            }), 400

        # Mettre à jour le statut des hôtes
        for host in target_hosts:
            db.execute(
                "UPDATE hosts SET status = 'deploying' WHERE name = ?",
                (host,)
            )
        db.commit()

        # Notifier le début du déploiement
        notify_deployment_start(environment, playbook, target_hosts)

        # Lancer le déploiement en arrière-plan
        threading.Thread(
            target=run_ansible_deployment, 
            args=(environment, playbook, target_hosts)
        ).start()

        return jsonify({
            'status': 'success',
            'message': f"Déploiement de {playbook} sur {len(target_hosts)} hôte(s) démarré!"
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Deployment failed: {str(e)}"
        }), 500

# --- Gestion des hôtes (suite) ---
@app.route('/hosts')
def list_hosts():
    db = get_db()
    hosts = db.execute('SELECT * FROM hosts ORDER BY added_date DESC').fetchall()
    return jsonify([dict(host) for host in hosts])

@app.route('/stats')
def get_stats():
    db = get_db()
    stats = db.execute('SELECT * FROM stats ORDER BY timestamp DESC LIMIT 1').fetchone()
    return jsonify(dict(stats)) if stats else jsonify({})

@app.route('/host/<int:host_id>', methods=['DELETE'])
def delete_host(host_id):
    try:
        db = get_db()
        
        # Récupérer l'hôte avant suppression
        host = db.execute('SELECT * FROM hosts WHERE id = ?', (host_id,)).fetchone()
        if not host:
            return jsonify({'status': 'error', 'message': 'Host not found'}), 404
        
        # Supprimer l'hôte
        db.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        db.commit()
        
        # Mettre à jour les statistiques
        update_stats()
        
        # Supprimer de l'inventaire
        remove_host_from_inventory(dict(host))
        
        return jsonify({
            'status': 'success',
            'message': f"Host {host['name']} deleted successfully!"
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Error deleting host: {str(e)}"
        }), 500

# Fonctions utilitaires
def save_host_to_inventory(host_data):
    env_dir = os.path.join(INVENTORY_DIR, host_data['environment'])
    os.makedirs(env_dir, exist_ok=True)
    
    inv_path = os.path.join(env_dir, 'hosts.yml')
    
    # Charger ou initialiser l'inventaire
    inventory = {'all': {'children': {}}}
    if os.path.exists(inv_path):
        with open(inv_path, 'r') as f:
            existing = yaml.safe_load(f)
            if existing:
                inventory = existing
    
    # S'assurer que la structure est correcte
    if 'children' not in inventory['all']:
        inventory['all']['children'] = {}
    
    # Ajouter l'hôte aux groupes
    groups = host_data['groups'].split(',') if host_data['groups'] else []
    for group in groups:
        if group not in inventory['all']['children']:
            inventory['all']['children'][group] = {'hosts': {}}
        
        # Initialiser les hosts si nécessaire
        if 'hosts' not in inventory['all']['children'][group]:
            inventory['all']['children'][group]['hosts'] = {}
        
        # Ajouter ou mettre à jour l'hôte
        inventory['all']['children'][group]['hosts'][host_data['name']] = {
            'ansible_host': host_data['ip'],
            'linsec_security_level': host_data['security_level']
        }
    
    # Sauvegarder l'inventaire
    with open(inv_path, 'w') as f:
        yaml.safe_dump(inventory, f, default_flow_style=False, sort_keys=False)

def remove_host_from_inventory(host_data):
    """Supprime un hôte de tous les inventaires Ansible"""
    env_dir = os.path.join(INVENTORY_DIR, host_data['environment'])
    inv_path = os.path.join(env_dir, 'hosts.yml')
    
    if not os.path.exists(inv_path):
        return
    
    try:
        with open(inv_path, 'r') as f:
            inventory = yaml.safe_load(f) or {'all': {'children': {}}}
        
        # Parcourir tous les groupes pour supprimer l'hôte
        host_name = host_data['name']
        for group in inventory['all']['children'].values():
            if 'hosts' in group and host_name in group['hosts']:
                del group['hosts'][host_name]
        
        # Sauvegarder l'inventaire modifié
        with open(inv_path, 'w') as f:
            yaml.safe_dump(inventory, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        app.logger.error(f"Failed to remove host from inventory: {str(e)}")

def run_ansible_deployment(environment, playbook, target_hosts):
    try:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        log_file = os.path.join(LOG_DIR, f"deploy-{environment}-{playbook}-{timestamp}.log")
        
        # Créer un fichier temporaire pour les variables
        env_file = os.path.join(LOG_DIR, f"env-{timestamp}.yml")
        with open(env_file, 'w') as f:
            yaml.safe_dump({'linsec_env': environment}, f)
        
        # Créer un fichier temporaire pour les hôtes
        hosts_file = os.path.join(LOG_DIR, f"hosts-{timestamp}.yml")
        with open(hosts_file, 'w') as f:
            yaml.safe_dump({'target_hosts': target_hosts}, f)
        
        cmd = [
            "ansible-playbook",
            "-i", os.path.join(INVENTORY_DIR, environment, "hosts.yml"),
            os.path.join(PLAYBOOKS_DIR, playbook),
            "--extra-vars", f"@{env_file}",
            "--extra-vars", f"@{hosts_file}",
            "--limit", ",".join(target_hosts)
        ]
        
        with open(log_file, 'w') as log:
            log.write(f"Starting deployment at {datetime.now()}\n")
            log.write(f"Command: {' '.join(cmd)}\n\n")
            log.flush()
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    cwd=ANSIBLE_DIR,
                    text=True
                )
                process.wait()
                
                log.write(f"\n\nDeployment finished at {datetime.now()}")
                log.write(f"\nExit code: {process.returncode}")
                
                # Mettre à jour le statut des hôtes après déploiement
                db = get_db()
                if process.returncode == 0:
                    for host in target_hosts:
                        db.execute(
                            "UPDATE hosts SET status = 'secured' WHERE name = ?",
                            (host,)
                        )
                    success = True
                else:
                    for host in target_hosts:
                        db.execute(
                            "UPDATE hosts SET status = 'error' WHERE name = ?",
                            (host,)
                        )
                    success = False
                db.commit()
                
                # Notifier la fin du déploiement
                notify_deployment_complete(environment, playbook, target_hosts, success)
                
            except Exception as e:
                log.write(f"\n\nERROR: {str(e)}")
                # Mettre à jour le statut en cas d'erreur
                db = get_db()
                for host in target_hosts:
                    db.execute(
                        "UPDATE hosts SET status = 'error' WHERE name = ?",
                        (host,)
                    )
                db.commit()
                notify_deployment_complete(environment, playbook, target_hosts, False)
                raise
            finally:
                try:
                    os.remove(env_file)
                    os.remove(hosts_file)
                except:
                    pass
        
        # Mettre à jour les statistiques
        update_stats()
        
    except Exception as e:
        app.logger.error(f"Deployment error: {str(e)}")

def update_stats():
    db = get_db()
    
    # Calculer les statistiques
    total_hosts = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
    secured_hosts = db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'secured'").fetchone()[0]
    unsecured_hosts = total_hosts - secured_hosts
    vulnerabilities = max(1, unsecured_hosts // 3)  # Au moins 1 vulnérabilité si hôtes non sécurisés
    
    # Insérer les nouvelles statistiques
    db.execute(
        'INSERT INTO stats (host_count, secured_count, vulnerabilities_count) '
        'VALUES (?, ?, ?)',
        (total_hosts, secured_hosts, vulnerabilities)
    )
    db.commit()

if __name__ == '__main__':
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(PLAYBOOKS_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)