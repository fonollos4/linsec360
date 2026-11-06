import { api } from './api.js';
import { state } from './state.js';
import { showNotification } from './notifications.js';

const pageTitles = {
    overview: "Vue d'ensemble",
    hosts: 'Hôtes',
    playbooks: 'Playbooks',
    deployments: 'Déploiements',
};

document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupForms();
    setupServerEvents();
    loadAll();
});

async function loadAll() {
    await Promise.all([loadHosts(), loadStats(), loadPlaybooks(), loadDeployments()]);
}

async function loadHosts() {
    try {
        state.hosts = await api.hosts();
        renderHosts();
        renderTargetHosts();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function loadStats() {
    try {
        renderStats(await api.stats());
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function loadPlaybooks() {
    try {
        state.playbooks = (await api.playbooks()).playbooks || [];
        renderPlaybooks();
        renderPlaybookSelect();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function loadDeployments() {
    try {
        state.deployments = await api.deployments();
        renderDeployments();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(button => {
        button.addEventListener('click', () => switchView(button.dataset.view));
    });
    document.querySelectorAll('[data-go]').forEach(button => {
        button.addEventListener('click', () => switchView(button.dataset.go));
    });
    document.getElementById('menu-button').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });
}

function switchView(view) {
    document.querySelectorAll('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.view === view));
    document.querySelectorAll('.view').forEach(panel => panel.classList.toggle('active', panel.dataset.viewPanel === view));
    document.getElementById('page-title').textContent = pageTitles[view];
    document.getElementById('sidebar').classList.remove('open');
}

function setupForms() {
    document.getElementById('top-action').addEventListener('click', () => openHostModal());
    document.getElementById('add-host-view-btn').addEventListener('click', () => openHostModal());
    document.getElementById('add-playbook-btn').addEventListener('click', () => openPlaybookModal());
    document.getElementById('library-search').addEventListener('input', renderPlaybooks);
    document.getElementById('refresh-deployments').addEventListener('click', loadDeployments);

    document.querySelectorAll('.modal-close').forEach(button => {
        button.addEventListener('click', () => button.closest('dialog').close());
    });
    document.getElementById('host-form').addEventListener('submit', addHost);
    document.getElementById('playbook-form').addEventListener('submit', savePlaybook);
    document.getElementById('deploy-form').addEventListener('submit', deploy);
    document.getElementById('target-type').addEventListener('change', updateTargetControls);
    document.getElementById('environment-select').addEventListener('change', renderTargetHosts);
}

function renderStats(stats) {
    const cards = [
        ['Hôtes enregistrés', stats.host_count || 0, '⌂'],
        ['Hôtes sécurisés', stats.secured_count || 0, '✓'],
        ['Vulnérabilités', stats.vulnerabilities_count ?? '—', '!'],
        ['Déploiements actifs', state.deployments?.filter(job => ['running', 'queued'].includes(job.status)).length || 0, '▶'],
    ];
    document.getElementById('stats-grid').innerHTML = cards.map(([label, value, icon]) => `
        <article class="stat-card"><div class="stat-card-top"><span>${label}</span><span class="stat-mark">${icon}</span></div><strong>${value}</strong></article>
    `).join('');
}

function renderHosts() {
    const body = document.getElementById('hosts-table');
    const overview = document.getElementById('overview-hosts');
    if (!state.hosts.length) {
        body.innerHTML = '<tr><td class="empty-row" colspan="6">Aucun hôte enregistré</td></tr>';
        overview.innerHTML = '<tr><td class="empty-row" colspan="4">Aucun hôte enregistré</td></tr>';
        return;
    }
    body.innerHTML = state.hosts.map(host => `
        <tr><td><strong>${escapeHtml(host.name)}</strong></td><td class="mono">${escapeHtml(host.ip)}</td>
        <td><span class="env-badge">${escapeHtml(host.environment || '-')}</span></td>
        <td><span class="status-badge ${escapeHtml(host.status)}">${statusLabel(host.status)}</span></td>
        <td>${escapeHtml(host.groups || '-')}</td>
        <td><button class="delete-button" data-delete-host="${host.id}" title="Supprimer l'hôte">×</button></td></tr>
    `).join('');
    overview.innerHTML = [...state.hosts].sort((a, b) => String(b.added_date).localeCompare(String(a.added_date))).slice(0, 5).map(host => `
        <tr><td><strong>${escapeHtml(host.name)}</strong></td><td class="mono">${escapeHtml(host.ip)}</td>
        <td><span class="env-badge">${escapeHtml(host.environment || '-')}</span></td>
        <td><span class="status-badge ${escapeHtml(host.status)}">${statusLabel(host.status)}</span></td></tr>
    `).join('');
    body.querySelectorAll('[data-delete-host]').forEach(button => {
        button.addEventListener('click', () => deleteHost(Number(button.dataset.deleteHost)));
    });
}

function getPlaybookDescription(filename) {
    const descriptions = {
        'connectivity.yml': 'Teste la connexion SSH et Ansible de chaque hôte.',
        'system-audit.yml': 'Collecte la distribution, le noyau et l architecture des serveurs.',
        'system-update.yml': 'Installe les mises à jour Debian, Ubuntu, RHEL et dérivés.',
        'disk-cleanup.yml': 'Supprime les anciens fichiers temporaires et nettoie les caches.',
    };
    return descriptions[filename] || 'Playbook Ansible personnalisable et prêt à être lancé.';
}

function launchPlaybook(filename) {
    switchView('overview');
    const select = document.getElementById('playbook-select');
    select.value = filename;
    document.getElementById('deploy-form').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function renderPlaybooks() {
    const grid = document.getElementById('playbooks-grid');
    const search = document.getElementById('library-search')?.value.trim().toLowerCase() || '';
    const playbooks = state.playbooks.filter(filename => {
        return !search || filename.toLowerCase().includes(search) || getPlaybookDescription(filename).toLowerCase().includes(search);
    });
    if (!state.playbooks.length) {
        grid.innerHTML = '<article class="panel playbook-card"><p class="empty-row">Aucun playbook disponible</p></article>';
        return;
    }
    if (!playbooks.length) {
        grid.innerHTML = '<article class="panel playbook-card"><p class="empty-row">Aucun playbook ne correspond à cette recherche</p></article>';
        return;
    }
    grid.innerHTML = playbooks.map(filename => `
        <article class="playbook-card">
            <div class="playbook-card-head"><span class="file-icon">{ }</span><h3>${escapeHtml(filename)}</h3></div>
            <span class="library-badge">Bibliothèque</span>
            <p>${getPlaybookDescription(filename)}</p>
            <div class="card-actions"><button data-launch-playbook="${escapeHtml(filename)}">Lancer</button><button data-edit-playbook="${escapeHtml(filename)}">Modifier</button><button data-delete-playbook="${escapeHtml(filename)}">Supprimer</button></div>
        </article>
    `).join('');
    grid.querySelectorAll('[data-launch-playbook]').forEach(button => button.addEventListener('click', () => launchPlaybook(button.dataset.launchPlaybook)));
    grid.querySelectorAll('[data-edit-playbook]').forEach(button => button.addEventListener('click', () => openPlaybookModal(button.dataset.editPlaybook)));
    grid.querySelectorAll('[data-delete-playbook]').forEach(button => button.addEventListener('click', () => deletePlaybook(button.dataset.deletePlaybook)));
}

function renderPlaybookSelect() {
    const select = document.getElementById('playbook-select');
    select.replaceChildren();
    if (!state.playbooks.length) {
        select.add(new Option('Aucun playbook disponible', ''));
        select.disabled = true;
        return;
    }
    select.disabled = false;
    state.playbooks.forEach(filename => select.add(new Option(filename, filename)));
    select.value = state.playbooks.includes('site.yml') ? 'site.yml' : state.playbooks[0];
}

function renderDeployments() {
    const body = document.getElementById('deployments-table');
    if (!state.deployments.length) {
        body.innerHTML = '<tr><td class="empty-row" colspan="6">Aucun déploiement enregistré</td></tr>';
        return;
    }
    body.innerHTML = state.deployments.map(job => `
        <tr><td class="mono">${escapeHtml(job.job_id.slice(0, 8))}</td><td><strong>${escapeHtml(job.playbook)}</strong></td>
        <td><span class="env-badge">${escapeHtml(job.environment)}</span></td><td>${job.target_hosts.length} hôte(s)</td>
        <td><span class="status-badge ${escapeHtml(job.status)}">${statusLabel(job.status)}</span></td>
        <td>${formatDate(job.created_at)}</td></tr>
    `).join('');
}

function renderTargetHosts() {
    const container = document.getElementById('host-selection');
    const environment = document.getElementById('environment-select').value;
    const hosts = state.hosts.filter(host => host.environment === environment);
    container.innerHTML = hosts.length
        ? hosts.map(host => `<label class="host-item"><input type="checkbox" value="${escapeHtml(host.name)}"><span>${escapeHtml(host.name)} · ${escapeHtml(host.ip)}</span></label>`).join('')
        : '<div class="empty-row">Aucun hôte dans cet environnement</div>';
}

function updateTargetControls() {
    const type = document.getElementById('target-type').value;
    document.getElementById('host-selection-container').hidden = type !== 'selected';
    document.getElementById('group-selection-container').hidden = type !== 'group';
    if (type === 'selected') renderTargetHosts();
}

function openHostModal() {
    document.getElementById('host-form').reset();
    document.getElementById('host-modal').showModal();
}

async function addHost(event) {
    event.preventDefault();
    const button = event.submitter;
    button.disabled = true;
    try {
        const result = await api.addHost(new FormData(event.target));
        document.getElementById('host-modal').close();
        showNotification(result.message, 'success');
        await loadHosts();
    } catch (error) {
        showNotification(error.message, 'error');
    } finally {
        button.disabled = false;
    }
}

async function deleteHost(id) {
    const host = state.hosts.find(item => item.id === id);
    if (!host || !confirm(`Supprimer l'hôte "${host.name}" ?`)) return;
    try {
        await api.deleteHost(id);
        showNotification(`Hôte ${host.name} supprimé`, 'success');
        await loadHosts();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function openPlaybookModal(filename = null) {
    const modal = document.getElementById('playbook-modal');
    const filenameInput = document.getElementById('playbook-filename');
    filenameInput.disabled = Boolean(filename);
    document.getElementById('playbook-modal-title').textContent = filename ? 'Modifier le playbook' : 'Nouveau playbook';
    filenameInput.value = filename || '';
    document.getElementById('playbook-content').value = '';
    if (filename) {
        try {
            const result = await api.playbook(filename);
            document.getElementById('playbook-content').value = result.content;
        } catch (error) {
            showNotification(error.message, 'error');
            return;
        }
    }
    modal.showModal();
}

async function savePlaybook(event) {
    event.preventDefault();
    const filename = document.getElementById('playbook-filename').value.trim();
    const content = document.getElementById('playbook-content').value;
    if (!filename || !/^[A-Za-z0-9_.-]+\.ya?ml$/.test(filename)) {
        showNotification('Utilisez un nom valide se terminant par .yml ou .yaml', 'warning');
        return;
    }
    try {
        const exists = state.playbooks.includes(filename);
        const result = exists ? await api.updatePlaybook(filename, content) : await api.addPlaybook(filename, content);
        document.getElementById('playbook-modal').close();
        showNotification(result.message, 'success');
        await loadPlaybooks();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function deletePlaybook(filename) {
    if (!confirm(`Supprimer le playbook "${filename}" ?`)) return;
    try {
        const result = await api.deletePlaybook(filename);
        showNotification(result.message, 'success');
        await loadPlaybooks();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function deploy(event) {
    event.preventDefault();
    const select = document.getElementById('playbook-select');
    if (!select.value) {
        showNotification('Aucun playbook disponible', 'warning');
        return;
    }
    const targetType = document.getElementById('target-type').value;
    const hosts = [...document.querySelectorAll('#host-selection input:checked')].map(input => input.value);
    if (targetType === 'selected' && !hosts.length) {
        showNotification('Sélectionnez au moins un hôte', 'warning');
        return;
    }
    if (!confirm(`Lancer "${select.value}" ?`)) return;
    try {
        const result = await api.deploy({
            environment: document.getElementById('environment-select').value,
            playbook: select.value,
            hosts,
            group: targetType === 'group' ? document.getElementById('group-select').value : null,
        });
        showNotification(result.message, 'success');
        await loadDeployments();
        switchView('deployments');
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function setupServerEvents() {
    const source = new EventSource('/events');
    source.onmessage = event => {
        try {
            const payload = JSON.parse(event.data);
            if (payload.type === 'stats') loadStats();
            if (payload.type === 'hosts') loadHosts();
            if (payload.type === 'deployment') {
                loadDeployments();
                if (payload.status !== 'running') showNotification(payload.message, payload.status === 'succeeded' ? 'success' : payload.status === 'failed' ? 'error' : 'info');
            }
        } catch (error) {
            console.error(error);
        }
    };
}

function statusLabel(status) {
    return ({ pending: 'En attente', secured: 'Sécurisé', deploying: 'Déploiement', running: 'En cours', succeeded: 'Réussi', failed: 'Échec', error: 'Erreur' })[status] || status || '-';
}
function formatDate(value) { return value ? new Date(value).toLocaleString('fr-FR') : '-'; }
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[character]);
}
