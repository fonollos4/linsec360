import os
from flask import Flask
from config import Config
from database import init_db_command, close_db
from routes import register_routes

def create_app():
    """Factory pour créer l'application Flask"""
    app = Flask(__name__, static_folder='static', static_url_path='/static')
    app.config.from_object(Config)
    
    # Initialiser la base de données
    app.cli.add_command(init_db_command)
    app.teardown_appcontext(close_db)
    
    # Enregistrer les routes
    register_routes(app)
    
    # Créer les répertoires nécessaires
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    os.makedirs(Config.PLAYBOOKS_DIR, exist_ok=True)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)