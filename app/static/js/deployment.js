export function createDeploymentRequest({
    targetType,
    environment,
    playbook,
    group,
    selectedHosts,
}) {
    return {
        environment,
        playbook,
        hosts: targetType === 'selected' ? selectedHosts : [],
        group: targetType === 'group' ? group : null,
    };
}

export function describeDeploymentTarget(targetType, environment, group, hostCount) {
    if (targetType === 'selected') {
        return `${hostCount} hôte(s) sélectionné(s)`;
    }
    if (targetType === 'group') {
        return `le groupe "${group}"`;
    }
    return `tous les hôtes de l'environnement "${environment}"`;
}
