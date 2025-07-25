# Use Debian Bookworm as base image
FROM python:3.13-bookworm

# Set the maintainer label
LABEL maintainer="Gloryd LOUGBEGNON"

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TIMEZONE=Africa/Porto-Novo \
    PYTHONUNBUFFERED=1
    
ARG USER=linsecagent
ARG ANSIBLE_CORE_VERSION=2.18
ARG ANSIBLE_VERSION

# Install system dependencies and Python tooling
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ssh \
    sudo \
    sshpass \
    git \
    curl \
    gnupg \
    libssl-dev \
    libffi-dev \
    gcc \
    jq \
    iputils-ping \
    sqlite3 \
    expect \
    ca-certificates && \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Upgrade pip and install the latest stable Ansible package (includes ansible-core)
RUN pip3 install --no-cache-dir --upgrade pip wheel && \
    pip3 install --no-cache-dir "ansible-core==${ANSIBLE_CORE_VERSION}" ansible

# Copy Ansible configuration into the image
COPY ./config/ansible/ansible.cfg /etc/ansible/ansible.cfg

# Create necessary directories for Linsec
RUN mkdir -p /opt/linsec/app && \
    mkdir -p /opt/linsec/taskengine && \
    mkdir -p /opt/linsec/logs/taskengine && \
    mkdir -p /opt/linsec/.ansible/tmp && \
    mkdir -p /opt/linsec/.ansible/fact_cache && \
    mkdir -p /opt/linsec/.ssh 

# Copy taskengine configuration files into the container
COPY ./taskengine/group_vars/ /opt/linsec/taskengine/group_vars/
COPY ./taskengine/host_vars/ /opt/linsec/taskengine/host_vars/
COPY ./taskengine/inventories/ /opt/linsec/taskengine/inventories/
COPY ./taskengine/library/ /opt/linsec/taskengine/library/
COPY ./taskengine/playbooks/ /opt/linsec/taskengine/playbooks/
COPY ./taskengine/roles/ /opt/linsec/taskengine/roles/
COPY ./taskengine/vars/ /opt/linsec/taskengine/vars/
   
# Set the working directory to the /opt/linsec/app directory
WORKDIR /opt/linsec/app

# Copy the requirements.txt file into the container
COPY ./app/requirements.txt /opt/linsec/app/requirements.txt

# Install Python dependencies from requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the entire web-ui directory into the container
COPY ./app .

# Initialize database
RUN sqlite3 /opt/linsec/app/instance/linsec.db < /opt/linsec/app/instance/schema.sql

# Create user to avoid use root account
RUN groupadd -r ${USER} && \
    useradd --create-home --shell /bin/bash --gid ${USER} -G sudo ${USER}  && \
    echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USER} && \
    chmod 0440 /etc/sudoers.d/${USER}

# Fix permissions for directories and files
RUN chown -R ${USER}:${USER} /opt/linsec && \
    chown -R ${USER}:${USER} /opt/linsec/app && \
    chown -R ${USER}:${USER} /opt/linsec/taskengine && \
    chown -R ${USER}:${USER} /opt/linsec/.ssh && \
    chown -R ${USER}:${USER} /opt/linsec/logs/ && \
    chmod 700 /opt/linsec && \
    find /opt/linsec -type d -exec chmod 755 {} \; && \
    find /opt/linsec -type f -exec chmod 644 {} \; && \
    find /opt/linsec/.ssh -type d -exec chmod 700 {} \; && \
    find /opt/linsec/.ssh -type f -exec chmod 600 {} \; 

# Copy and chmod the entrypoint script
COPY ./config/ansible/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to non-privileged user for runtime
USER ${USER}
    
# Expose the Flask port
EXPOSE 5000

# Use entrypoint script as default
ENTRYPOINT ["/entrypoint.sh"]