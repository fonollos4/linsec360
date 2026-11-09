# Active response policy

LinSec360 exposes only two operator-confirmed Wazuh active responses:

- `firewall-drop`
- `disable-account`

## Safety requirements

- Only `admin` and `operator` roles may submit a response.
- The API request must include `confirm: true`.
- A Wazuh agent ID must be present on the alert.
- Every submission is recorded in the immutable audit log.
- Wazuh and the indexer/API credentials must be configured.

The execution endpoint is `POST /api/v1/alerts/{alert_id}/active-response`.
The action is sent through the configured Wazuh API and is never simulated
when Wazuh is unavailable.
