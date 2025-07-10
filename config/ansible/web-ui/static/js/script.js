// Éléments DOM
const addHostBtn = document.getElementById('add-host-btn');
const deployBtn = document.getElementById('deploy-btn');
const hostModal = document.getElementById('host-modal');
const closeBtn = document.querySelector('.close-btn');
const cancelBtn = document.getElementById('cancel-btn');
const hostForm = document.getElementById('host-form');
const hostsTable = document.getElementById('hosts-table').getElementsByTagName('tbody')[0];
const hostCountEl = document.getElementById('host-count');
const securedCountEl = document.getElementById('secured-count');
const vulnerabilitiesCountEl = document.getElementById('vulnerabilities-count');
const lastUpdateEl = document.getElementById('last-update');

// Variables globales
let hosts = [];
let lastStats = {
    host_count: 0,
    secured_count: 0,
    vulnerabilities_count: 0,
    last_update: '--/--/----'
};

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    // Charger les données initiales
    fetchHosts();
    fetchStats();
    
    // Configurer les écouteurs d'événements
    setupEventListeners();
    
    // Actualiser les données toutes les 30 secondes
    setInterval(fetchStats, 30000);
});

// Configuration des écouteurs d'événements
function setupEventListeners() {
    // Gestion de la modale
    addHostBtn.addEventListener('click', () => {
        hostModal.style.display = 'flex';
    });

    closeBtn.addEventListener('click', () => {
        hostModal.style.display = 'none';
    });

    cancelBtn.addEventListener('click', () => {
        hostModal.style.display = 'none';
        hostForm.reset();
    });

    window.addEventListener('click', (e) => {
        if (e.target === hostModal) {
            hostModal.style.display = 'none';
            hostForm.reset();
        }
    });

    // Soumission du formulaire
    hostForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await addNewHost();
    });

    // Déploiement
    deployBtn.addEventListener('click', async () => {
        await deployConfiguration();
    });
}

// Fonction pour ajouter un nouvel hôte
async function addNewHost() {
    const formData = new FormData(hostForm);
    const groups = formData.getAll('groups');
    
    const hostData = {
        hostname: formData.get('hostname'),
        ip: formData.get('ip'),
        environment: formData.get('environment'),
        groups: groups,
        'security-level': formData.get('security-level')
    };
    
    try {
        const response = await fetch('/add-host', {
            method: 'POST',
            body: new URLSearchParams(hostData)
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'success');
            hostModal.style.display = 'none';
            hostForm.reset();
            
            // Actualiser les données
            fetchHosts();
            fetchStats();
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Fonction pour lancer le déploiement
async function deployConfiguration() {
    try {
        const response = await fetch('/deploy', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ environment: 'production' })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'info');
            
            // Actualiser les données après un délai (simulation)
            setTimeout(() => {
                fetchStats();
                showNotification('Déploiement réussi! Tous les hôtes sont sécurisés.', 'success');
            }, 5000);
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Récupérer la liste des hôtes depuis le serveur
async function fetchHosts() {
    try {
        const response = await fetch('/hosts');
        const data = await response.json();
        
        if (Array.isArray(data)) {
            hosts = data;
            renderHostsTable();
        }
    } catch (error) {
        console.error('Erreur lors de la récupération des hôtes:', error);
        showNotification('Impossible de charger la liste des hôtes', 'error');
    }
}

// Récupérer les statistiques depuis le serveur
async function fetchStats() {
    try {
        const response = await fetch('/stats');
        const data = await response.json();
        
        if (data) {
            lastStats = data;
            updateStats();
        }
    } catch (error) {
        console.error('Erreur lors de la récupération des statistiques:', error);
    }
}

// Afficher le tableau des hôtes
function renderHostsTable() {
    hostsTable.innerHTML = '';
    
    // Trier par date récente (simulé)
    const recentHosts = [...hosts].sort((a, b) => 
        b.id - a.id
    ).slice(0, 5);
    
    recentHosts.forEach(host => {
        const row = hostsTable.insertRow();
        
        // Nom
        const nameCell = row.insertCell();
        nameCell.textContent = host.name;
        
        // IP
        const ipCell = row.insertCell();
        ipCell.textContent = host.ip;
        
        // Environnement
        const envCell = row.insertCell();
        envCell.innerHTML = `<span class="env-badge ${host.environment}">${host.environment}</span>`;
        
        // Statut
        const statusCell = row.insertCell();
        statusCell.innerHTML = `<span class="status-badge ${host.status}">${getStatusText(host.status)}</span>`;
        
        // Actions
        const actionCell = row.insertCell();
        actionCell.innerHTML = `
            <button class="action-btn view-btn" data-id="${host.id}">
                <i class="fas fa-eye"></i>
            </button>
            <button class="action-btn edit-btn" data-id="${host.id}">
                <i class="fas fa-edit"></i>
            </button>
            <button class="action-btn delete-btn" data-id="${host.id}">
                <i class="fas fa-trash"></i>
            </button>
        `;
    });
    
    // Ajouter les écouteurs d'événements pour les boutons
    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const hostId = parseInt(e.target.closest('button').dataset.id);
            await deleteHost(hostId);
        });
    });
}

// Supprimer un hôte
async function deleteHost(id) {
    try {
        // Envoyer la requête de suppression au serveur
        const response = await fetch(`/hosts/${id}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'success');
            
            // Actualiser les données
            fetchHosts();
            fetchStats();
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Mettre à jour les statistiques affichées
function updateStats() {
    hostCountEl.textContent = lastStats.host_count || 0;
    securedCountEl.textContent = lastStats.secured_count || 0;
    vulnerabilitiesCountEl.textContent = lastStats.vulnerabilities_count || 0;
    lastUpdateEl.textContent = lastStats.last_update || '--/--/----';
}

function getStatusText(status) {
    const statusMap = {
        'pending': 'En attente',
        'secured': 'Sécurisé',
        'warning': 'Avertissement',
        'error': 'Erreur'
    };
    return statusMap[status] || status;
}

// Afficher une notification
function showNotification(message, type) {
    // Créer l'élément de notification
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : 
                            type === 'warning' ? 'fa-exclamation-triangle' : 
                            type === 'info' ? 'fa-info-circle' : 'fa-exclamation-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    // Ajouter à la page
    document.body.appendChild(notification);
    
    // Supprimer après 5 secondes
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 5000);
}

// Ajouter le CSS pour les notifications si nécessaire
if (!document.querySelector('#notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 5px;
        color: white;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 3000;
        opacity: 0;
        transform: translateY(-20px);
        animation: fadeIn 0.5s forwards;
    }

    @keyframes fadeIn {
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .notification.success {
        background: linear-gradient(135deg, #2ecc71, #27ae60);
    }

    .notification.warning {
        background: linear-gradient(135deg, #f39c12, #d35400);
    }

    .notification.info {
        background: linear-gradient(135deg, #3498db, #2980b9);
    }

    .notification.error {
        background: linear-gradient(135deg, #e74c3c, #c0392b);
    }

    .notification-content {
        display: flex;
        align-items: center;
    }

    .notification-content i {
        margin-right: 10px;
        font-size: 1.2rem;
    }
    `;
    document.head.appendChild(style);
}