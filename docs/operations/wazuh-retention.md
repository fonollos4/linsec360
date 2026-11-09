# Wazuh retention and alert tuning

## Retention

Store alert and index retention independently:

- define an Index Lifecycle Management policy for `wazuh-alerts-*`;
- keep a minimum hot/warm period compatible with incident response;
- export any legally required evidence before rollover or deletion;
- align LinSec360 database retention with the deployment retention setting.

## Recommended index template

Use Wazuh's packaged template for schema compatibility. Custom LinSec360
searches should only add keyword mappings and aliases; they must not replace
Wazuh's official mappings.

## Alert tuning

- start with Wazuh's authentication, privilege escalation, process execution,
  and file-integrity groups enabled;
- record an owner and ticket for every suppression rule;
- tune with agent, rule level, decoder, and MITRE filters rather than global
  suppressions;
- review unacknowledged critical/high alerts during each maintenance window.
