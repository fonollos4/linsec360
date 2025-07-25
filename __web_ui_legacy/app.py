import os
import sqlite3
from flask import Flask, render_template, request, jsonify, g
from datetime import datetime
import subprocess
import threading

app = Flask(__name__, static_folder='static', static_url_path='/static', template_folder='templates')

app.secret_key = os.environ.get('FLASK_SECRET', 'supersecretkey')

# Configuration paths
INVENTORY_DIR = "/ansible/inventory"
ANSIBLE_DIR = "/ansible"
LOG_DIR = "/var/log/linsec"
DATABASE = os.path.join(app.instance_path, 'linsec.db')

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

# Routes principales
@app.route('/')
def index():
    db = get_db()
    stats = db.execute('SELECT * FROM stats ORDER BY timestamp DESC LIMIT 1').fetchone()
    hosts = db.execute('SELECT * FROM hosts ORDER BY added_date DESC LIMIT 5').fetchall()
    
    return render_template('index.html', 
                           stats=stats or {},
                           hosts=hosts or [])

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

@app.route('/deploy', methods=['POST'])
def deploy():
    try:
        environment = request.json.get('environment', 'production')
        
        # Mettre à jour le statut des hôtes
        db = get_db()
        db.execute(
            "UPDATE hosts SET status = 'deploying' WHERE environment = ?",
            (environment,)
        )
        db.commit()
        
        # Lancer le déploiement en arrière-plan
        threading.Thread(
            target=run_ansible_deployment, 
            args=(environment,)
        ).start()
        
        return jsonify({
            'status': 'success',
            'message': f"Deployment to {environment} started successfully!"
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Deployment failed: {str(e)}"
        }), 500

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
            import yaml
            inventory = yaml.safe_load(f) or inventory
    
    # Ajouter l'hôte aux groupes
    groups = host_data['groups'].split(',') if host_data['groups'] else []
    for group in groups:
        if group not in inventory['all']['children']:
            inventory['all']['children'][group] = {'hosts': {}}
        
        inventory['all']['children'][group]['hosts'][host_data['name']] = {
            'ansible_host': host_data['ip'],
            'linsec_security_level': host_data['security_level']
        }
    
    # Sauvegarder l'inventaire
    with open(inv_path, 'w') as f:
        yaml.dump(inventory, f, default_flow_style=False)

def run_ansible_deployment(environment):
    try:
        log_file = os.path.join(LOG_DIR, f"deploy-{environment}-{datetime.now().strftime('%Y%m%d%H%M%S')}.log")
        
        cmd = [
            "ansible-playbook",
            "-i", os.path.join(INVENTORY_DIR, environment, "hosts.yml"),
            os.path.join(ANSIBLE_DIR, "playbooks", "site.yml"),
            "--extra-vars", f"linsec_env={environment}"
        ]
        
        with open(log_file, 'w') as log:
            process = subprocess.Popen(
                cmd,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=ANSIBLE_DIR
            )
            process.wait()
        
        # Mettre à jour le statut des hôtes après déploiement
        db = get_db()
        if process.returncode == 0:
            db.execute(
                "UPDATE hosts SET status = 'secured' WHERE environment = ? AND status = 'deploying'",
                (environment,)
            )
        else:
            db.execute(
                "UPDATE hosts SET status = 'error' WHERE environment = ? AND status = 'deploying'",
                (environment,)
            )
        db.commit()
        
        # Mettre à jour les statistiques
        update_stats()
        
    except Exception as e:
        print(f"Deployment error: {str(e)}")
        # Mettre à jour le statut en cas d'erreur
        db = get_db()
        db.execute(
            "UPDATE hosts SET status = 'error' WHERE environment = ? AND status = 'deploying'",
            (environment,)
        )
        db.commit()

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
    app.run(host='0.0.0.0', port=5000, debug=True)