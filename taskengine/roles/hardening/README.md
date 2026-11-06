# hardening role

Applies the LinSec360 Linux baseline and writes a machine-readable drift
report. The role is safe to run in check mode:

```bash
ansible-playbook -i inventories/production/hosts.yml \
  playbooks/hardening.yml --check --limit web01
```

## What it manages

- SSH: root login, password auth, auth attempts, idle timeout.
- sysctl: ASLR, SYN cookies, forwarding, redirects, protected links, dmesg.
- auditd: package, immutable rules from `config/selinux/audit.rules`.
- PAM: `pwquality` and `faillock` policies.
- Packages: removes legacy remote-access services.
- SELinux: mode, policy type, and baseline booleans.

## Drift reporting

The role writes `/var/log/linsec/<host>-hardening.json` on each host. The
`hardening.yml` playbook fetches it to
`artifacts/hardening/<host>-hardening.json` on the controller.

Set `hardening_ingest_url` and `hardening_api_token` to POST results to
`/api/v1/hardening/results` automatically. Without those values the report is
only written to disk, and LinSec360 keeps the host's hardening state `unknown`
rather than inventing values.

## Important variables

| Variable | Default | Purpose |
|---|---|---|
| `hardening_apply` | `true` | Set `false` for audit-only runs |
| `hardening_selinux_mode` | `enforcing` | SELinux mode written to config |
| `hardening_remove_packages` | legacy services | Package deny list |
| `hardening_ingest_url` | empty | LinSec360 API base URL |

SELinux mode changes take effect after reboot. The role does not reboot hosts.
