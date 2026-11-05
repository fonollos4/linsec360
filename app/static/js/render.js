const STATUS_LABELS = {
    pending: 'En attente',
    secured: 'Sécurisé',
    deploying: 'Déploiement en cours',
    error: 'Erreur',
};

export function renderHostsTable(hosts, onDelete) {
    const body = document.querySelector('#hosts-table tbody');
    body.replaceChildren();

    const recentHosts = [...hosts]
        .sort((left, right) => new Date(right.added_date) - new Date(left.added_date))
        .slice(0, 5);

    if (recentHosts.length === 0) {
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.className = 'no-hosts';
        cell.textContent = 'Aucun hôte enregistré';
        return;
    }

    for (const host of recentHosts) {
        const row = body.insertRow();
        row.insertCell().textContent = host.name;
        row.insertCell().textContent = host.ip;

        const environmentCell = row.insertCell();
        const environmentBadge = document.createElement('span');
        environmentBadge.className = 'env-badge';
        environmentBadge.textContent = host.environment;
        environmentCell.appendChild(environmentBadge);

        const statusCell = row.insertCell();
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge ${host.status}`;
        statusBadge.textContent = STATUS_LABELS[host.status] || host.status;
        statusCell.appendChild(statusBadge);

        const actionsCell = row.insertCell();
        const deleteButton = document.createElement('button');
        deleteButton.className = 'action-btn delete-btn';
        deleteButton.type = 'button';
        deleteButton.textContent = '×';
        deleteButton.title = 'Supprimer cet hôte';
        deleteButton.addEventListener('click', () => onDelete(host));
        actionsCell.appendChild(deleteButton);
    }
}

export function renderHostSelection(hosts, environment, selectedNames = []) {
    const selection = document.getElementById('host-selection');
    selection.replaceChildren();
    const matchingHosts = hosts.filter(host => host.environment === environment);

    if (matchingHosts.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'no-hosts';
        emptyState.textContent = 'Aucun hôte dans cet environnement';
        selection.appendChild(emptyState);
        return;
    }

    for (const host of matchingHosts) {
        const item = document.createElement('label');
        item.className = 'host-item';

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = host.name;
        checkbox.checked = selectedNames.includes(host.name);

        const details = document.createElement('span');
        details.textContent = `${host.name} — ${host.ip}`;
        item.append(checkbox, details);
        selection.appendChild(item);
    }
}

export function renderStats(stats) {
    document.getElementById('host-count').textContent = stats.host_count || 0;
    document.getElementById('secured-count').textContent = stats.secured_count || 0;
    document.getElementById('vulnerabilities-count').textContent =
        stats.vulnerabilities_count || 0;

    const lastUpdate = document.getElementById('last-update');
    lastUpdate.textContent = stats.timestamp
        ? new Date(stats.timestamp).toLocaleString('fr-FR')
        : '--/--/----';
}

export function renderPlaybooks(playbooks) {
    const select = document.getElementById('playbook-select');
    select.replaceChildren();

    if (playbooks.length === 0) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'Aucun playbook disponible';
        select.appendChild(option);
        select.disabled = true;
        return;
    }

    select.disabled = false;
    for (const playbook of playbooks) {
        const option = document.createElement('option');
        option.value = playbook;
        option.textContent = playbook;
        select.appendChild(option);
    }
    select.value = playbooks.includes('site.yml') ? 'site.yml' : playbooks[0];
}
