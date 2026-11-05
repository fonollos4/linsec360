async function requestJson(path, options = {}) {
    const response = await fetch(path, options);
    const result = await response.json();
    if (!response.ok) {
        throw new Error(result.message || response.statusText);
    }
    return result;
}

export const api = {
    hosts: () => requestJson('/hosts'),
    stats: () => requestJson('/stats'),
    playbooks: () => requestJson('/playbooks'),
    addHost(formData) {
        const payload = new URLSearchParams();
        for (const [key, value] of formData.entries()) {
            payload.append(key, value);
        }
        return requestJson('/add-host', { method: 'POST', body: payload });
    },
    deleteHost(id) {
        return requestJson(`/host/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },
    deploy(payload) {
        return requestJson('/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
    },
};
