import os
import sqlite3
import click
from flask import current_app, g
from flask.cli import with_appcontext
from config import Config

def get_db():
    """Obtenir la connexion à la base de données"""
    if 'db' not in g:
        g.db = sqlite3.connect(Config.get_database_path())
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(error):
    """Fermer la connexion à la base de données"""
    if hasattr(g, 'db'):
        g.db.close()

def init_db():
    """Initialiser la base de données"""
    os.makedirs(current_app.instance_path, exist_ok=True)
    
    db = sqlite3.connect(Config.get_database_path())
    with current_app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Commande CLI pour initialiser la base de données"""
    init_db()
    click.echo('Base de données initialisée.')

class DatabaseManager:
    """Gestionnaire pour les opérations de base de données"""
    
    @staticmethod
    def get_all_hosts():
        """Récupérer tous les hôtes"""
        db = get_db()
        return db.execute('SELECT * FROM hosts ORDER BY added_date DESC').fetchall()
    
    @staticmethod
    def get_host_by_id(host_id):
        """Récupérer un hôte par son ID"""
        db = get_db()
        return db.execute('SELECT * FROM hosts WHERE id = ?', (host_id,)).fetchone()
    
    @staticmethod
    def add_host(host_data):
        """Ajouter un hôte à la base de données"""
        db = get_db()
        db.execute(
            'INSERT INTO hosts (name, ip, environment, security_level, groups, status) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (host_data['name'], host_data['ip'], host_data['environment'], 
             host_data['security_level'], host_data['groups'], host_data['status'])
        )
        db.commit()
    
    @staticmethod
    def update_host_status(host_name, status):
        """Mettre à jour le statut d'un hôte"""
        db = get_db()
        db.execute("UPDATE hosts SET status = ? WHERE name = ?", (status, host_name))
        db.commit()
    
    @staticmethod
    def update_hosts_status(host_names, status):
        """Mettre à jour le statut de plusieurs hôtes"""
        db = get_db()
        for host_name in host_names:
            db.execute("UPDATE hosts SET status = ? WHERE name = ?", (status, host_name))
        db.commit()
    
    @staticmethod
    def delete_host(host_id):
        """Supprimer un hôte"""
        db = get_db()
        host = DatabaseManager.get_host_by_id(host_id)
        if host:
            db.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
            db.commit()
            return dict(host)
        return None
    
    @staticmethod
    def get_hosts_by_environment(environment):
        """Récupérer les hôtes d'un environnement"""
        db = get_db()
        return db.execute(
            "SELECT name FROM hosts WHERE environment = ?", (environment,)
        ).fetchall()
    
    @staticmethod
    def get_hosts_by_group(group, environment):
        """Récupérer les hôtes d'un groupe dans un environnement"""
        db = get_db()
        return db.execute(
            "SELECT name FROM hosts WHERE groups LIKE ? AND environment = ?",
            (f'%{group}%', environment)
        ).fetchall()
    
    @staticmethod
    def get_latest_stats():
        """Récupérer les dernières statistiques"""
        db = get_db()
        return db.execute('SELECT * FROM stats ORDER BY timestamp DESC LIMIT 1').fetchone()
    
    @staticmethod
    def update_stats():
        """Mettre à jour les statistiques"""
        db = get_db()
        
        # Calculer les statistiques
        total_hosts = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
        secured_hosts = db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'secured'").fetchone()[0]
        unsecured_hosts = total_hosts - secured_hosts
        vulnerabilities = max(1, unsecured_hosts // 3) if unsecured_hosts > 0 else 0
        
        # Insérer les nouvelles statistiques
        db.execute(
            'INSERT INTO stats (host_count, secured_count, vulnerabilities_count) '
            'VALUES (?, ?, ?)',
            (total_hosts, secured_hosts, vulnerabilities)
        )
        db.commit()