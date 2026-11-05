import os
import sqlite3
import click
from flask import current_app, g
from flask.cli import with_appcontext
from config import Config

def get_db():
    """Obtenir la connexion à la base de données"""
    if 'db' not in g:
        g.db = sqlite3.connect(Config.get_database_path(), timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(error):
    """Fermer la connexion à la base de données"""
    if hasattr(g, 'db'):
        g.db.close()

def init_db():
    """Initialize database"""
    os.makedirs(current_app.instance_path, exist_ok=True)
    
    db = sqlite3.connect(Config.get_database_path(), timeout=10)
    try:
        with current_app.open_resource('instance/schema.sql', mode='r') as schema_file:
            db.cursor().executescript(schema_file.read())
        db.commit()
    finally:
        db.close()

@click.command('init-db')
@with_appcontext
def init_db_command():
    """CLI Command to init the database"""
    init_db()
    click.echo('Database initialize.')