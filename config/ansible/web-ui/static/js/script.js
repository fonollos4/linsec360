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
const playbookSelect = document.getElementById('playbook-select');
const environmentSelect = document.getElementById('environment-select');
const targetTypeSelect = document.getElementById('target-type');
const hostSelectionContainer = document.getElementById('host-selection-container');
const hostSelection = document.getElementById('host-selection');
const groupSelectionContainer = document.getElementById('group-selection-container');
const selectAllBtn = document.getElementById('select-all');
const deselectAllBtn = document.getElementById('deselect-all');

// Variables globales
let hosts = [];
let lastStats = {
    host_count: 0,
    secured_count: 0,
    vulnerabilities_count: 0,
    timestamp: '--/--/----'
};
let playbooks = [];
let eventSource = null;

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    fetchHosts();
    fetchStats();
    fetchPlaybooks();
    setupEventListeners();
    setupServerSentEvents();
    
    // Écouter les changements de cible de déploiement
    targetTypeSelect.addEventListener('change', updateTargetSelection);
});

// Configuration des écouteurs d'événements
function setupEventListeners() {
    addHostBtn.addEventListener('click', () => hostModal.style.display = 'flex');
    closeBtn.addEventListener('click', () => hostModal.style.display = 'none');
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
    hostForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await addNewHost();
    });
    deployBtn.addEventListener('click', async () => {
        await deployConfiguration();
    });
    selectAllBtn.addEventListener('click', () => {
        document.querySelectorAll('#host-selection input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = true;
        });
    });
    deselectAllBtn.addEventListener('click', () => {
        document.querySelectorAll('#host-selection input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = false;
        });
    });
}

// Mise à jour de l'affichage de sélection
function updateTargetSelection() {
    const targetType = targetTypeSelect.value;
    
    // Masquer tous les conteneurs
    hostSelectionContainer.style.display = 'none';
    groupSelectionContainer.style.display = 'none';
    
    // Afficher le conteneur approprié
    if (targetType === 'selected') {
        hostSelectionContainer.style.display = 'block';
        populateHostSelection();
    } else if (targetType === 'group') {
        groupSelectionContainer.style.display = 'block';
    }
}

// Remplir la sélection d'hôtes
function populateHostSelection() {
    hostSelection.innerHTML = '';
    
    hosts.forEach(host => {
        const hostItem = document.createElement('div');
        hostItem.className = 'host-item';
        
        hostItem.innerHTML = `
            <input type="checkbox" id="host-${host.id}" value="${host.name}">
            <div class="host-info">
                <div class="host-name">${host.name}</div>
                <div class="host-details">${host.ip} | ${host.environment}</div>
            </div>
        `;
        
        hostSelection.appendChild(hostItem);
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
        'security-level': formData.get('security-level'),
        groups: groups
    };
    
    // Validation de l'adresse IP
    if (!validateIP(hostData.ip)) {
        showNotification('Adresse IP invalide. Format attendu: xxx.xxx.xxx.xxx', 'error');
        return;
    }
    
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
            fetchHosts();
            fetchStats();
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Validation d'adresse IP
function validateIP(ip) {
    const ipPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipPattern.test(ip);
}

// Fonction pour lancer le déploiement
async function deployConfiguration() {
    const playbook = playbookSelect.value;
    const environment = environmentSelect.value;
    const targetType = targetTypeSelect.value;
    
    let targetHosts = [];
    let targetGroup = null;
    
    // Déterminer les cibles
    if (targetType === 'selected') {
        // Récupérer les hôtes sélectionnés
        document.querySelectorAll('#host-selection input:checked').forEach(checkbox => {
            targetHosts.push(checkbox.value);
        });
        
        if (targetHosts.length === 0) {
            showNotification('Veuillez sélectionner au moins un hôte', 'warning');
            return;
        }
    } else if (targetType === 'group') {
        targetGroup = document.getElementById('group-select').value;
    }
    
    // Confirmation
    let message;
    if (targetType === 'all') {
        message = `Êtes-vous sûr de vouloir déployer le playbook "${playbook}" sur tous les hôtes de l'environnement "${environment}" ?`;
    } else if (targetType === 'selected') {
        message = `Êtes-vous sûr de vouloir déployer le playbook "${playbook}" sur ${targetHosts.length} hôte(s) sélectionné(s) ?`;
    } else if (targetType === 'group') {
        message = `Êtes-vous sûr de vouloir déployer le playbook "${playbook}" sur le groupe "${targetGroup}" ?`;
    }
    
    const confirmation = confirm(message);
    if (!confirmation) return;
    
    try {
        const response = await fetch('/deploy', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                environment: environment,
                playbook: playbook,
                hosts: targetHosts,
                group: targetGroup
            })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'info');
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Configuration des Server-Sent Events
function setupServerSentEvents() {
    if (eventSource) {
        eventSource.close();
    }
    
    eventSource = new EventSource('/events');
    
    eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'stats') {
            lastStats = data.data;
            updateStatsDisplay();
        }
        
        if (data.type === 'hosts') {
            hosts = data.data;
            renderHostsTable();
            // Mettre à jour la sélection d'hôtes si visible
            if (hostSelectionContainer.style.display === 'block') {
                populateHostSelection();
            }
        }
        
        if (data.type === 'deployment') {
            showNotification(data.message, data.status === 'deploying' ? 'info' : data.status);
        }
    };
    
    eventSource.onerror = (error) => {
        console.error('Erreur SSE:', error);
        // Tentative de reconnexion après un délai
        setTimeout(setupServerSentEvents, 5000);
    };
}

// Récupérer la liste des playbooks
async function fetchPlaybooks() {
    try {
        const response = await fetch('/playbooks');
        const result = await response.json();
        
        if (result.status === 'success') {
            playbooks = result.playbooks;
            updatePlaybookSelect();
        } else {
            showNotification('Erreur lors du chargement des playbooks: ' + result.message, 'error');
        }
    } catch (error) {
        console.error('Erreur lors du chargement des playbooks:', error);
        showNotification('Impossible de charger les playbooks', 'error');
    }
}

// Mettre à jour le sélecteur de playbooks
function updatePlaybookSelect() {
    playbookSelect.innerHTML = '';
    
    playbooks.forEach(playbook => {
        const option = document.createElement('option');
        option.value = playbook;
        option.textContent = playbook;
        playbookSelect.appendChild(option);
    });
    
    // Sélectionner 'site.yml' par défaut s'il existe
    if (playbooks.includes('site.yml')) {
        playbookSelect.value = 'site.yml';
    }
}

// Récupérer la liste des hôtes
async function fetchHosts() {
    try {
        const response = await fetch('/hosts');
        if (!response.ok) {
            throw new Error('Erreur réseau');
        }
        hosts = await response.json();
        renderHostsTable();
    } catch (error) {
        console.error('Erreur lors de la récupération des hôtes:', error);
        showNotification('Impossible de charger la liste des hôtes', 'error');
    }
}

// Récupérer les statistiques
async function fetchStats() {
    try {
        const response = await fetch('/stats');
        if (!response.ok) {
            throw new Error('Erreur réseau');
        }
        lastStats = await response.json();
        updateStatsDisplay();
    } catch (error) {
        console.error('Erreur lors de la récupération des statistiques:', error);
    }
}

// Afficher le tableau des hôtes
function renderHostsTable() {
    hostsTable.innerHTML = '';
    
    // Limiter aux 5 hôtes les plus récents
    const recentHosts = [...hosts]
        .sort((a, b) => new Date(b.added_date) - new Date(a.added_date))
        .slice(0, 5);
    
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
        const envBadge = document.createElement('span');
        envBadge.className = `env-badge`;
        envBadge.textContent = host.environment;
        envCell.appendChild(envBadge);
        
        // Statut
        const statusCell = row.insertCell();
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge ${host.status}`;
        statusBadge.textContent = getStatusText(host.status);
        statusCell.appendChild(statusBadge);
        
        // Actions
        const actionCell = row.insertCell();
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'action-btn delete-btn';
        deleteBtn.dataset.id = host.id;
        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
        actionCell.appendChild(deleteBtn);
        
        // Ajouter l'écouteur d'événement pour le bouton de suppression
        deleteBtn.addEventListener('click', async (e) => {
            await deleteHost(host.id);
        });
    });
}

// Supprimer un hôte
async function deleteHost(id) {
    const confirmation = confirm('Êtes-vous sûr de vouloir supprimer cet hôte ?');
    if (!confirmation) return;
    
    try {
        const response = await fetch(`/host/${id}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'success');
            fetchHosts();
            fetchStats();
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Mettre à jour l'affichage des statistiques
function updateStatsDisplay() {
    hostCountEl.textContent = lastStats.host_count || 0;
    securedCountEl.textContent = lastStats.secured_count || 0;
    vulnerabilitiesCountEl.textContent = lastStats.vulnerabilities_count || 0;
    
    if (lastStats.timestamp) {
        const date = new Date(lastStats.timestamp);
        lastUpdateEl.textContent = date.toLocaleDateString('fr-FR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } else {
        lastUpdateEl.textContent = '--/--/----';
    }
}

function getStatusText(status) {
    const statusMap = {
        'pending': 'En attente',
        'secured': 'Sécurisé',
        'deploying': 'Déploiement en cours',
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
const playbookSelect = document.getElementById('playbook-select');
const environmentSelect = document.getElementById('environment-select');
const targetTypeSelect = document.getElementById('target-type');
const hostSelectionContainer = document.getElementById('host-selection-container');
const hostSelection = document.getElementById('host-selection');
const groupSelectionContainer = document.getElementById('group-selection-container');
const selectAllBtn = document.getElementById('select-all');
const deselectAllBtn = document.getElementById('deselect-all');

// Variables globales
let hosts = [];
let lastStats = {
    host_count: 0,
    secured_count: 0,
    vulnerabilities_count: 0,
    timestamp: '--/--/----'
};
let playbooks = [];
let eventSource = null;

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    fetchInitialData();
    setupEventListeners();
    setupServerSentEvents();
    
    // Écouter les changements de cible de déploiement
    targetTypeSelect.addEventListener('change', updateTargetSelection);
});

// Récupérer toutes les données initiales
async function fetchInitialData() {
    try {
        const response = await fetch('/initial-data');
        const data = await response.json();
        
        // Mettre à jour les hôtes
        hosts = data.hosts || [];
        renderHostsTable();
        
        // Mettre à jour les statistiques
        lastStats = data.stats || {};
        updateStatsDisplay();
        
        // Mettre à jour les playbooks
        playbooks = data.playbooks || [];
        updatePlaybookSelect();
    } catch (error) {
        console.error('Erreur lors du chargement des données initiales:', error);
        showNotification('Impossible de charger les données initiales', 'error');
    }
}

// Configuration des écouteurs d'événements
function setupEventListeners() {
    // Gestion de la modal d'ajout d'hôte
    addHostBtn.addEventListener('click', () => hostModal.style.display = 'flex');
    closeBtn.addEventListener('click', () => hostModal.style.display = 'none');
    cancelBtn.addEventListener('click', () => {
        hostModal.style.display = 'none';
        hostForm.reset();
    });
    
    // Fermer la modal en cliquant en dehors
    window.addEventListener('click', (e) => {
        if (e.target === hostModal) {
            hostModal.style.display = 'none';
            hostForm.reset();
        }
    });
    
    // Soumission du formulaire d'hôte
    hostForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await addNewHost();
    });
    
    // Bouton de déploiement
    deployBtn.addEventListener('click', async () => {
        await deployConfiguration();
    });
    
    // Sélection/désélection de tous les hôtes
    selectAllBtn.addEventListener('click', () => {
        document.querySelectorAll('#host-selection input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = true;
        });
    });
    
    deselectAllBtn.addEventListener('click', () => {
        document.querySelectorAll('#host-selection input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = false;
        });
    });
}

// Mise à jour de l'affichage de sélection
function updateTargetSelection() {
    const targetType = targetTypeSelect.value;
    
    // Masquer tous les conteneurs
    hostSelectionContainer.style.display = 'none';
    groupSelectionContainer.style.display = 'none';
    
    // Afficher le conteneur approprié
    if (targetType === 'selected') {
        hostSelectionContainer.style.display = 'block';
        populateHostSelection();
    } else if (targetType === 'group') {
        groupSelectionContainer.style.display = 'block';
    }
}

// Remplir la sélection d'hôtes
function populateHostSelection() {
    hostSelection.innerHTML = '';
    
    if (hosts.length === 0) {
        hostSelection.innerHTML = '<div class="no-hosts">Aucun hôte disponible</div>';
        return;
    }
    
    hosts.forEach(host => {
        const hostItem = document.createElement('div');
        hostItem.className = 'host-item';
        
        hostItem.innerHTML = `
            <input type="checkbox" id="host-${host.id}" value="${host.name}">
            <div class="host-info">
                <div class="host-name">${host.name}</div>
                <div class="host-details">
                    <span class="host-ip">${host.ip}</span> | 
                    <span class="host-env">${host.environment}</span>
                </div>
                <span class="status-badge ${host.status}">${getStatusText(host.status)}</span>
            </div>
        `;
        
        hostSelection.appendChild(hostItem);
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
        'security-level': formData.get('security-level'),
        groups: groups
    };
    
    // Validation de l'adresse IP
    if (!validateIP(hostData.ip)) {
        showNotification('Adresse IP invalide. Format attendu: xxx.xxx.xxx.xxx', 'error');
        return;
    }
    
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
            fetchInitialData();
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Validation d'adresse IP
function validateIP(ip) {
    const ipPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipPattern.test(ip);
}

// Fonction pour lancer le déploiement
async function deployConfiguration() {
    const playbook = playbookSelect.value;
    const environment = environmentSelect.value;
    const targetType = targetTypeSelect.value;
    
    let targetHosts = [];
    let targetGroup = null;
    
    // Déterminer les cibles
    if (targetType === 'selected') {
        // Récupérer les hôtes sélectionnés
        document.querySelectorAll('#host-selection input:checked').forEach(checkbox => {
            targetHosts.push(checkbox.value);
        });
        
        if (targetHosts.length === 0) {
            showNotification('Veuillez sélectionner au moins un hôte', 'warning');
            return;
        }
    } else if (targetType === 'group') {
        targetGroup = document.getElementById('group-select').value;
    }
    
    // Confirmation
    const message = getDeploymentConfirmationMessage(targetType, playbook, environment, targetGroup, targetHosts.length);
    const confirmation = confirm(message);
    if (!confirmation) return;
    
    try {
        const response = await fetch('/deploy', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                environment: environment,
                playbook: playbook,
                hosts: targetHosts,
                group: targetGroup
            })
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'info');
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Générer le message de confirmation de déploiement
function getDeploymentConfirmationMessage(targetType, playbook, environment, group, hostCount) {
    switch (targetType) {
        case 'all':
            return `Êtes-vous sûr de vouloir déployer le playbook "${playbook}" sur tous les hôtes de l'environnement "${environment}" ?`;
        case 'selected':
            return `Êtes-vous sûr de vouloir déployer le playbook "${playbook}" sur ${hostCount} hôte(s) sélectionné(s) ?`;
        case 'group':
            return `Êtes-vous sûr de vouloir déployer le playbook "${playbook}" sur le groupe "${group}" ?`;
        default:
            return 'Êtes-vous sûr de vouloir lancer ce déploiement ?';
    }
}

// Configuration des Server-Sent Events
function setupServerSentEvents() {
    if (eventSource) {
        eventSource.close();
    }
    
    eventSource = new EventSource('/events');
    
    eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleSSEData(data);
        } catch (error) {
            console.error('Erreur de parsing SSE:', error);
        }
    };
    
    eventSource.onerror = (error) => {
        console.error('Erreur SSE:', error);
        // Tentative de reconnexion après un délai
        setTimeout(setupServerSentEvents, 5000);
    };
}

// Traiter les données SSE
function handleSSEData(data) {
    if (data.type === 'stats') {
        lastStats = data.data || {};
        updateStatsDisplay();
    }
    
    if (data.type === 'hosts') {
        hosts = data.data || [];
        renderHostsTable();
        
        // Mettre à jour la sélection d'hôtes si visible
        if (hostSelectionContainer.style.display === 'block') {
            populateHostSelection();
        }
    }
    
    if (data.type === 'deployment') {
        let notificationType = 'info';
        if (data.status === 'secured') notificationType = 'success';
        else if (data.status === 'error') notificationType = 'error';
        
        showNotification(data.message, notificationType);
    }
}

// Mettre à jour le sélecteur de playbooks
function updatePlaybookSelect() {
    playbookSelect.innerHTML = '';
    
    if (playbooks.length === 0) {
        playbookSelect.innerHTML = '<option value="">Aucun playbook disponible</option>';
        return;
    }
    
    playbooks.forEach(playbook => {
        const option = document.createElement('option');
        option.value = playbook;
        option.textContent = playbook;
        playbookSelect.appendChild(option);
    });
    
    // Sélectionner 'site.yml' par défaut s'il existe
    if (playbooks.includes('site.yml')) {
        playbookSelect.value = 'site.yml';
    }
}

// Afficher le tableau des hôtes
function renderHostsTable() {
    hostsTable.innerHTML = '';
    
    if (hosts.length === 0) {
        hostsTable.innerHTML = '<tr><td colspan="5" class="no-hosts">Aucun hôte enregistré</td></tr>';
        return;
    }
    
    // Limiter aux 5 hôtes les plus récents
    const recentHosts = [...hosts]
        .sort((a, b) => new Date(b.added_date) - new Date(a.added_date))
        .slice(0, 5);
    
    recentHosts.forEach(host => {
        const row = hostsTable.insertRow();
        row.dataset.id = host.id;
        
        // Nom
        const nameCell = row.insertCell();
        nameCell.textContent = host.name;
        
        // IP
        const ipCell = row.insertCell();
        ipCell.textContent = host.ip;
        
        // Environnement
        const envCell = row.insertCell();
        const envBadge = document.createElement('span');
        envBadge.className = `env-badge ${host.environment.toLowerCase()}`;
        envBadge.textContent = host.environment;
        envCell.appendChild(envBadge);
        
        // Statut
        const statusCell = row.insertCell();
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge ${host.status}`;
        statusBadge.textContent = getStatusText(host.status);
        statusCell.appendChild(statusBadge);
        
        // Actions
        const actionCell = row.insertCell();
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'action-btn delete-btn';
        deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
        deleteBtn.title = 'Supprimer cet hôte';
        actionCell.appendChild(deleteBtn);
        
        // Ajouter l'écouteur d'événement pour le bouton de suppression
        deleteBtn.addEventListener('click', () => deleteHost(host.id));
    });
}

// Supprimer un hôte
async function deleteHost(id) {
    const host = hosts.find(h => h.id === id);
    if (!host) return;
    
    const confirmation = confirm(`Êtes-vous sûr de vouloir supprimer l'hôte "${host.name}" ?`);
    if (!confirmation) return;
    
    try {
        const response = await fetch(`/host/${id}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.status === 'success') {
            showNotification(result.message, 'success');
            // Actualiser les données
            fetchInitialData();
        } else {
            showNotification(result.message, 'error');
        }
    } catch (error) {
        showNotification(`Erreur réseau: ${error.message}`, 'error');
    }
}

// Mettre à jour l'affichage des statistiques
function updateStatsDisplay() {
    hostCountEl.textContent = lastStats.host_count || 0;
    securedCountEl.textContent = lastStats.secured_count || 0;
    vulnerabilitiesCountEl.textContent = lastStats.vulnerabilities_count || 0;
    
    if (lastStats.timestamp) {
        const date = new Date(lastStats.timestamp);
        lastUpdateEl.textContent = date.toLocaleDateString('fr-FR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } else {
        lastUpdateEl.textContent = '--/--/----';
    }
}

function getStatusText(status) {
    const statusMap = {
        'pending': 'En attente',
        'secured': 'Sécurisé',
        'deploying': 'Déploiement en cours',
        'error': 'Erreur'
    };
    return statusMap[status] || status;
}

// Afficher une notification
function showNotification(message, type) {
    // Créer l'élément de notification
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Icônes selon le type
    let iconClass;
    switch (type) {
        case 'success': iconClass = 'fa-check-circle'; break;
        case 'warning': iconClass = 'fa-exclamation-triangle'; break;
        case 'info': iconClass = 'fa-info-circle'; break;
        default: iconClass = 'fa-exclamation-circle';
    }
    
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${iconClass}"></i>
            <span>${message}</span>
        </div>
        <div class="notification-progress ${type}"></div>
    `;
    
    // Ajouter à la page
    document.body.appendChild(notification);
    
    // Animation d'apparition
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateY(0)';
    }, 10);
    
    // Animation de progression
    const progress = notification.querySelector('.notification-progress');
    progress.style.width = '100%';
    progress.style.transition = 'width 5s linear';
    
    // Supprimer après 5 secondes
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateY(-100%)';
        
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 5000);
}
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