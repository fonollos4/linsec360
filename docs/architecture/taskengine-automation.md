# Taskengine hardening and patching baseline

All active LinSec360 automation lives under `taskengine/`. The legacy UI and
worker keep their existing playbook seeding and deployment flow; this document
describes the new, explicit baseline that operators can run from a checkout.

## Entry points

Run commands from `taskengine/` so `ansible.cfg` resolves the local inventory
and role paths:

```bash
cd taskengine
ansible-playbook -i inventories/production/hosts.yml playbooks/site.yml
ansible-playbook -i inventories/production/hosts.yml playbooks/verify.yml
```

- `playbooks/site.yml` applies the four baseline roles in order.
- `playbooks/verify.yml` is read-only and fails with an explicit message when a
  required control is missing.
- `playbooks/openscap-scan.yml`, `playbooks/openscap-remediate.yml` and
  `playbooks/compliance-verify.yml` implement the compliance workflow.
- `playbooks/patch-security.yml` and `playbooks/patch-verify.yml` apply and
  verify targeted native fixes. `playbooks/livepatch-check.yml` reports the
  kernel live-patch state.

Hosts must belong to `redhat_family` or `debian_family` in
`inventories/production/hosts.yml` (or in the API-generated inventory).

## Roles

| Role | Purpose |
|---|---|
| `cleanup_uyuni` | Stops/disables Salt/Uyuni services, removes client packages, legacy repositories and configuration, then guarantees that SSH is started and enabled. |
| `hardening_mac` | Enforces SELinux on RedHat-family hosts and AppArmor on Debian-family hosts without disabling critical SSH profiles. |
| `hardening_openscap` | Audits before/after remediation, filters generated fixes, writes XML/HTML reports and a status log for Wazuh. |
| `patching_option2` | Role name retained for compatibility; configures native security updates, Ubuntu Pro livepatch when a vaulted token is provided, and a Wazuh `full_command` status script. |

Every role is written to be idempotent: a second run must leave stable tasks
at `changed=0`. No task stops, disables or masks `sshd`/`ssh`.

## OpenSCAP audit and remediation

The audit command keeps the required shape:

```text
oscap xccdf eval --profile <profile> --results <xml> --report <html> <datastream>
```

Before and after results are written under `/var/log/linsec360/`:

- `oscap-before.xml` / `oscap-before.html`
- `oscap-after.xml` / `oscap-after.html`
- `openscap-status.log` (consumed by the Wazuh agent)

`rc == 1` fails the run. `rc == 2` is accepted because it means failed or
unknown rules, not an evaluation error.

Remediation is generated with `oscap xccdf generate fix`, then passed through
`filter_oscap_remediation.py`. The policy excludes rule IDs and shell lines
that could disable SSH or interfere with Wazuh ports `1514`/`1515`. Only the
filtered script is applied.

## Native patching workflow

- RedHat-family hosts use `dnf-automatic` in security mode with
  `apply_updates = yes` and `dnf-automatic.timer`.
- Debian-family hosts use `unattended-upgrades` and `apt-daily-upgrade.timer`.
- Reboots are never forced during working hours. They remain manual unless an
  operator explicitly sets `patching_automatic_reboot` with an out-of-hours
  time.
- Ubuntu attaches to Pro with the vaulted `ubuntu_pro_token` variable and runs
  `pro enable livepatch --assume-yes` only when needed. The token is never
  logged (`no_log: true`).
- `/usr/local/bin/check_patching_status.sh` is deployed for Wazuh command
  monitoring.

## Uyuni retirement

Uyuni is no longer deployed or injected into runtime configuration, worker
extra variables, the UI, or Compose. The legacy backend modules and patching
API endpoints remain importable but are inactive when no Uyuni credentials are
configured, so existing integrations are not broken. Orphaned `uyuni_*`
runtime settings are removed when the configuration is reset.

## Verification

After applying the baseline, verify it with:

```bash
cd taskengine
ansible-playbook -i inventories/production/hosts.yml playbooks/verify.yml
```

The verification checks Salt/Uyuni absence, SELinux `Enforcing` or active
AppArmor, a usable `oscap-after.html`, `wazuh-agent`, `sshd`/`ssh`, Ubuntu
`canonical-livepatch` where applicable, and the enabled update timer.
