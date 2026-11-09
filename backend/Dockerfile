FROM python:3.12-slim

ARG LINSEC_UID=1000
ARG LINSEC_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/opt/linsec

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        sshpass \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/linsec

COPY backend/requirements.txt /tmp/requirements.txt
COPY taskengine/requirements.yml /tmp/ansible-collections.yml
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir "ansible-core==2.18.*" \
    && ansible-galaxy collection install \
        -r /tmp/ansible-collections.yml \
        --collections-path /usr/share/ansible/collections

COPY backend /opt/linsec/backend
COPY taskengine/playbooks /opt/linsec/taskengine/playbooks
COPY taskengine/roles /opt/linsec/taskengine/roles
# Automation assets referenced by the hardening, OpenSCAP and live-patch
# playbooks. Keep the copy narrow so generated keys/certs are not baked in.
COPY config/hardening /opt/linsec/config/hardening
COPY config/selinux /opt/linsec/config/selinux
COPY config/openscap /opt/linsec/config/openscap
COPY config/scripts /opt/linsec/config/scripts
COPY backend/ansible.cfg /etc/ansible/ansible.cfg

RUN groupadd --gid "${LINSEC_GID}" linsec \
    && useradd --uid "${LINSEC_UID}" --gid linsec --create-home \
        --home-dir /home/linsec linsec \
    && mkdir -p \
        /opt/linsec/logs \
        /opt/linsec/var/playbooks \
        /opt/linsec/var/inventories \
        /opt/linsec/taskengine/inventories \
        /opt/linsec/taskengine/.ansible/tmp \
        /opt/linsec/taskengine/.ansible/fact_cache \
        /opt/linsec/taskengine/library \
        /opt/linsec/.ssh \
    && chown -R linsec:linsec /opt/linsec /home/linsec \
    && chmod 700 /opt/linsec/.ssh

USER linsec
EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
