import { api } from './api.js';
import {
    createDeploymentRequest,
    describeDeploymentTarget,
} from './deployment.js';
import { showNotification } from './notifications.js';
import {
    renderHostSelection,
    renderHostsTable,
    renderPlaybooks,
    renderStats,
} from './render.js';
import { state } from './state.js';

document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    setupServerSentEvents();
    loadDashboard();
});

async function loadDashboard() {
    try {
        const [hostData, stats, playbookResult] = await Promise.all([
            api.hosts(),
            api.stats(),
            api.playbooks(),
        ]);
        state.hosts = hostData;
        renderHostsTable(state.hosts, deleteHost);
        renderStats(stats);
        renderPlaybooks(playbookResult.playbooks);
        updateTargetSelection();
    } catch (error) {
        console.error('Unable to load dashboard data', error);
        showNotification(`Impossible de charger le tableau de bord: ${error.message}`, 'error');
    }
}

function setupEventListeners() {
    const modal = document.getElementById('host-modal');
    const form = document.getElementById('host-form');

    document.getElementById('add-host-btn').addEventListener('click', () => {
        modal.style.display = 'flex';
    });
    document.querySelector('.close-btn').addEventListener('click', closeHostModal);
    document.getElementById('cancel-btn').addEventListener('click', closeHostModal);
    window.addEventListener('click', event => {
        if (event.target === modal) closeHostModal();
    });

    form.addEventListener('submit', async event => {
        event.preventDefault();
        try {
            const result = await api.addHost(new FormData(form));
            showNotification(result.message, 'success');
            closeHostModal();
            form.reset();
            await loadDashboard();
        } catch (error) {
            showNotification(error.message, 'error');
        }
    });

    document.getElementById('deploy-btn').addEventListener('click', deployConfiguration);
    document.getElementById('target-type').addEventListener('change', updateTargetSelection);
    document.getElementById('environment-select').addEventListener('change', () => {
        if (document.getElementById('target-type').value === 'selected') {
            updateTargetSelection();
        }
    });
    document.getElementById('select-all').addEventListener('click', () => {
        document.querySelectorAll('#host-selection input[type="checkbox"]')
            .forEach(checkbox => { checkbox.checked = true; });
    });
    document.getElementById('deselect-all').addEventListener('click', () => {
        document.querySelectorAll('#host-selection input[type="checkbox"]')
            .forEach(checkbox => { checkbox.checked = false; });
    });
}

function closeHostModal() {
    document.getElementById('host-modal').style.display = 'none';
    document.getElementById('host-form').reset();
}

function updateTargetSelection() {
    const targetType = document.getElementById('target-type').value;
    const hostContainer = document.getElementById('host-selection-container');
    const groupContainer = document.getElementById('group-selection-container');
    const selectedNames = [...document.querySelectorAll('#host-selection input:checked')]
        .map(checkbox => checkbox.value);

    hostContainer.style.display = targetType === 'selected' ? 'block' : 'none';
    groupContainer.style.display = targetType === 'group' ? 'block' : 'none';
    if (targetType === 'selected') {
        renderHostSelection(
            state.hosts,
            document.getElementById('environment-select').value,
            selectedNames,
        );
    }
}

async function deleteHost(host) {
    if (!confirm(`Êtes-vous sûr de vouloir supprimer l'hôte "${host.name}" ?`)) return;
    try {
        const result = await api.deleteHost(host.id);
        showNotification(result.message, 'success');
        await loadDashboard();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function deployConfiguration() {
    const targetType = document.getElementById('target-type').value;
    const environment = document.getElementById('environment-select').value;
    const playbook = document.getElementById('playbook-select').value;
    const selectedHosts = [...document.querySelectorAll('#host-selection input:checked')]
        .map(checkbox => checkbox.value);
    const group = targetType === 'group'
        ? document.getElementById('group-select').value
        : null;

    if (!playbook) {
        showNotification('Aucun playbook disponible', 'warning');
        return;
    }
    if (targetType === 'selected' && selectedHosts.length === 0) {
        showNotification('Veuillez sélectionner au moins un hôte', 'warning');
        return;
    }

    const targetDescription = describeDeploymentTarget(
        targetType,
        environment,
        group,
        selectedHosts.length,
    );
    if (!confirm(`Déployer "${playbook}" sur ${targetDescription} ?`)) return;

    try {
        const result = await api.deploy(createDeploymentRequest({
            environment,
            targetType,
            playbook,
            group,
            selectedHosts,
        }));
        showNotification(`${result.message} (ID: ${result.job_id})`, 'info');
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function setupServerSentEvents() {
    const eventSource = new EventSource('/events');
    eventSource.onmessage = event => {
        try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'stats') {
                renderStats(payload.data || {});
            } else if (payload.type === 'hosts') {
                state.hosts = payload.data || [];
                renderHostsTable(state.hosts, deleteHost);
                updateTargetSelection();
            } else if (payload.type === 'deployment' && payload.status !== 'running') {
                const notificationType = payload.status === 'succeeded'
                    ? 'success'
                    : payload.status === 'failed'
                        ? 'error'
                        : 'info';
                showNotification(payload.message, notificationType);
            }
        } catch (error) {
            console.error('Unable to process server event', error);
        }
    };
    eventSource.onerror = error => {
        console.error('Server event stream disconnected', error);
    };
}
