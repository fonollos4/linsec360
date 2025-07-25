import os
import yaml
import subprocess
import threading
import time
import json
from datetime import datetime
from flask import current_app
from config import Config
from database import DatabaseManager

class ValidationService:
    """Service pour valider les données"""
    
    @staticmethod
    def validate_ip(ip):
        """Valider une adresse IPv4"""
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
    
    @staticmethod
    def validate_playbook_name(filename):
        """Valider le nom d'un playbook"""
        return filename and (filename.endswith('.yml') or filename.endswith('.yaml'))

class InventoryService:
    """Service pour gérer les inventaires Ansible"""
    
    @staticmethod
    def save_host_to_inventory(host_data):
        """Sauvegarder un hôte dans l'inventaire Ansible"""
        env_dir = os.path.join(Config.INVENTORY_DIR, host_data['environment'])
        os.makedirs(env_dir, exist_ok=True)
        
        inv_path = Config.get_inventory_path(host_data['environment'])
        
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
    
    @staticmethod
    def remove_host_from_inventory(host_data):
        """Supprimer un hôte de l'inventaire Ansible"""
        inv_path = Config.get_inventory_path(host_data['environment'])
        
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
            current_app.logger.error(f"Échec de suppression de l'hôte de l'inventaire: {str(e)}")

class PlaybookService:
    """Service pour gérer les playbooks"""
    
    @staticmethod
    def list_playbooks():
        """Lister tous les playbooks disponibles"""
        os.makedirs(Config.PLAYBOOKS_DIR, exist_ok=True)
        files = os.listdir(Config.PLAYBOOKS_DIR)
        return [f for f in files if f.endswith('.yml') or f.endswith('.yaml')]
    
    @staticmethod
    def create_playbook(filename, content):
        """Créer un nouveau playbook"""
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Le nom du fichier doit se terminer par .yml ou .yaml")
        
        filepath = Config.get_playbook_path(filename)
        if os.path.exists(filepath):
            raise ValueError("Le playbook existe déjà")
        
        with open(filepath, 'w') as f:
            f.write(content)
    
    @staticmethod
    def update_playbook(filename, content):
        """Mettre à jour un playbook existant"""
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        
        filepath = Config.get_playbook_path(filename)
        if not os.path.exists(filepath):
            raise ValueError("Playbook non trouvé")
        
        with open(filepath, 'w') as f:
            f.write(content)
    
    @staticmethod
    def delete_playbook(filename):
        """Supprimer un playbook"""
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        
        filepath = Config.get_playbook_path(filename)
        if not os.path.exists(filepath):
            raise ValueError("Playbook non trouvé")
        
        os.remove(filepath)

class DeploymentService:
    """Service pour gérer les déploiements"""
    
    @staticmethod
    def get_target_hosts(environment, target_hosts=None, target_group=None):
        """Déterminer les hôtes cibles pour le déploiement"""
        if target_group:
            # Récupérer les hôtes du groupe
            hosts = DatabaseManager.get_hosts_by_group(target_group, environment)
            return [host['name'] for host in hosts]
        elif target_hosts:
            return target_hosts
        else:
            # Tous les hôtes de l'environnement
            hosts = DatabaseManager.get_hosts_by_environment(environment)
            return [host['name'] for host in hosts]
    
    @staticmethod
    def start_deployment(environment, playbook, target_hosts):
        """Démarrer un déploiement"""
        # Valider que le playbook existe
        playbook_path = Config.get_playbook_path(playbook)
        if not os.path.isfile(playbook_path):
            raise ValueError(f"Le playbook {playbook} n'existe pas")
        
        if not target_hosts:
            raise ValueError('Aucun hôte à déployer')
        
        # Mettre à jour le statut des hôtes
        DatabaseManager.update_hosts_status(target_hosts, 'deploying')
        
        # Notifier le début du déploiement
        EventService.notify_deployment_start(environment, playbook, target_hosts)
        
        # Lancer le déploiement en arrière-plan
        threading.Thread(
            target=DeploymentService._run_ansible_deployment,
            args=(environment, playbook, target_hosts)
        ).start()
    
    @staticmethod
    def _run_ansible_deployment(environment, playbook, target_hosts):
        """Exécuter le déploiement Ansible"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            log_file = os.path.join(Config.LOG_DIR, f"deploy-{environment}-{playbook}-{timestamp}.log")
            
            # Créer un fichier temporaire pour les variables
            env_file = os.path.join(Config.LOG_DIR, f"env-{timestamp}.yml")
            with open(env_file, 'w') as f:
                yaml.safe_dump({'linsec_env': environment}, f)
            
            # Créer un fichier temporaire pour les hôtes
            hosts_file = os.path.join(Config.LOG_DIR, f"hosts-{timestamp}.yml")
            with open(hosts_file, 'w') as f:
                yaml.safe_dump({'target_hosts': target_hosts}, f)
            
            cmd = [
                "ansible-playbook",
                "-i", Config.get_inventory_path(environment),
                Config.get_playbook_path(playbook),
                "--extra-vars", f"@{env_file}",
                "--extra-vars", f"@{hosts_file}",
                "--limit", ",".join(target_hosts)
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
                    
                    # Mettre à jour le statut des hôtes après déploiement
                    if process.returncode == 0:
                        DatabaseManager.update_hosts_status(target_hosts, 'secured')
                        success = True
                    else:
                        DatabaseManager.update_hosts_status(target_hosts, 'error')
                        success = False
                    
                    # Notifier la fin du déploiement
                    EventService.notify_deployment_complete(environment, playbook, target_hosts, success)
                    
                except Exception as e:
                    log.write(f"\n\nERREUR: {str(e)}")
                    DatabaseManager.update_hosts_status(target_hosts, 'error')
                    EventService.notify_deployment_complete(environment, playbook, target_hosts, False)
                    raise
                finally:
                    # Nettoyer les fichiers temporaires
                    for temp_file in [env_file, hosts_file]:
                        try:
                            os.remove(temp_file)
                        except:
                            pass
            
            # Mettre à jour les statistiques
            DatabaseManager.update_stats()
            
        except Exception as e:
            current_app.logger.error(f"Erreur de déploiement: {str(e)}")

class EventService:
    """Service pour gérer les événements en temps réel"""
    
    EVENT_LISTENERS = []
    
    @staticmethod
    def get_event_stream():
        """Générateur pour le flux d'événements SSE"""
        while True:
            if EventService.EVENT_LISTENERS:
                # Vérifier les mises à jour chaque seconde
                time.sleep(1)
                stats = DatabaseManager.get_latest_stats()
                hosts = DatabaseManager.get_all_hosts()
                
                # Envoyer la mise à jour des stats
                stats_data = {
                    'type': 'stats',
                    'data': dict(stats) if stats else {}
                }
                yield f"data: {json.dumps(stats_data)}\n\n"
                
                # Envoyer la mise à jour des hôtes
                hosts_data = {
                    'type': 'hosts',
                    'data': [dict(host) for host in hosts]
                }
                yield f"data: {json.dumps(hosts_data)}\n\n"
            else:
                time.sleep(5)
    
    @staticmethod
    def notify_deployment_start(environment, playbook, hosts):
        """Notifier le début d'un déploiement"""
        deployment_data = {
            'type': 'deployment',
            'message': f"Déploiement de {playbook} sur {len(hosts)} hôte(s) démarré",
            'status': 'deploying',
            'hosts': hosts
        }
        EventService.EVENT_LISTENERS.append(deployment_data)
    
    @staticmethod
    def notify_deployment_complete(environment, playbook, hosts, success):
        """Notifier la fin d'un déploiement"""
        status = 'secured' if success else 'error'
        message = f"Déploiement de {playbook} sur {len(hosts)} hôte(s) terminé avec succès" if success \
            else f"Échec du déploiement de {playbook} sur {len(hosts)} hôte(s)"
        
        deployment_data = {
            'type': 'deployment',
            'message': message,
            'status': status,
            'hosts': hosts
        }
        EventService.EVENT_LISTENERS.append(deployment_data)