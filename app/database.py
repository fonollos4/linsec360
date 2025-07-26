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
    """Initialize database"""
    os.makedirs(current_app.instance_path, exist_ok=True)
    
    db = sqlite3.connect(Config.get_database_path())
    with current_app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """CLI Command to init the database"""
    init_db()
    click.echo('Database initialize.')

class DatabaseManager:
    """Database operations manager"""
    
    @staticmethod
    def get_all_hosts():
        """Get all hosts"""
        db = get_db()
        return db.execute('SELECT * FROM hosts ORDER BY added_date DESC').fetchall()
    
    @staticmethod
    def get_host_by_id(host_id):
        """Get host by ID"""
        db = get_db()
        return db.execute('SELECT * FROM hosts WHERE id = ?', (host_id,)).fetchone()
    
    @staticmethod
    def add_host(host_data):
        """Add a new host to the database"""
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
        """Update hosts status"""
        db = get_db()
        db.execute("UPDATE hosts SET status = ? WHERE name = ?", (status, host_name))
        db.commit()
    
    @staticmethod
    def update_hosts_status(host_names, status):
        """Update multiple hosts status"""
        db = get_db()
        for host_name in host_names:
            db.execute("UPDATE hosts SET status = ? WHERE name = ?", (status, host_name))
        db.commit()
    
    @staticmethod
    def delete_host(host_id):
        """Delete host"""
        db = get_db()
        host = DatabaseManager.get_host_by_id(host_id)
        if host:
            db.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
            db.commit()
            return dict(host)
        return None
    
    @staticmethod
    def get_hosts_by_environment(environment):
        """Get hosts of specific environment"""
        db = get_db()
        return db.execute(
            "SELECT name FROM hosts WHERE environment = ?", (environment,)
        ).fetchall()
    
    @staticmethod
    def get_hosts_by_group(group, environment):
        """Get hosts of specific group in an environment"""
        db = get_db()
        return db.execute(
            "SELECT name FROM hosts WHERE groups LIKE ? AND environment = ?",
            (f'%{group}%', environment)
        ).fetchall()
    
    @staticmethod
    def get_latest_stats():
        """Get the latest statistics"""
        db = get_db()
        return db.execute('SELECT * FROM stats ORDER BY timestamp DESC LIMIT 1').fetchone()
    
    @staticmethod
    def update_stats():
        """Update statistics"""
        db = get_db()
        
        # Calculate statistics
        total_hosts = db.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]
        secured_hosts = db.execute("SELECT COUNT(*) FROM hosts WHERE status = 'secured'").fetchone()[0]
        unsecured_hosts = total_hosts - secured_hosts
        vulnerabilities = max(1, unsecured_hosts // 3) if unsecured_hosts > 0 else 0
        
        # Insert the new statistics
        db.execute(
            'INSERT INTO stats (host_count, secured_count, vulnerabilities_count) '
            'VALUES (?, ?, ?)',
            (total_hosts, secured_hosts, vulnerabilities)
        )
        db.commit()