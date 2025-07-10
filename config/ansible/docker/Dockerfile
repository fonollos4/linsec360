# Use Debian Bookworm as base image
FROM python:3.13.5-bookworm

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1
    

ARG ANSIBLE_CORE_VERSION=2.18
ARG ANSIBLE_VERSION

# Install system dependencies and Python tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    ssh \
    sshpass \
    git \
    curl \
    gnupg \
    libssl-dev \
    libffi-dev \
    gcc \
    jq \
    iputils-ping \
    expect \
    ca-certificates && \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Upgrade pip and install the latest stable Ansible package (includes ansible-core)
RUN pip3 install --no-cache-dir --upgrade pip wheel && \
    pip3 install --no-cache-dir "ansible-core==${ANSIBLE_CORE_VERSION}" ansible

# Create and set permissions on directories
RUN mkdir -p /ansible \
    /var/log/ansible && \
    chmod 0755 /ansible /var/log/ansible

# Copy Ansible configuration into the image
COPY ansible.cfg /etc/ansible/ansible.cfg

# Copy invetory ssh setup script into the image
COPY setup_ssh_inventory.sh /ansible

# Copy and chmod the entrypoint script
COPY ./docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory to your mounted Ansible project
WORKDIR /ansible

# Use entrypoint script as default
ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash", "-c", "tail -f /dev/null"]
