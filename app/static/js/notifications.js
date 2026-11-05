export function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    const text = document.createElement('span');
    text.textContent = message;
    notification.appendChild(text);
    document.body.appendChild(notification);

    window.setTimeout(() => {
        notification.remove();
    }, 5000);
}
