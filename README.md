# jira-cs-sync

This can be used to sync a Jira Issues to Crowdstrike Alerts and Incidents.

## Overview

This script synchronizes CrowdStrike incident and alert data with a JIRA Cloud project using the CrowdStrike SOAR JIRA plugin. The SOAR workflow creates an incident or alert as a JIRA issue and appends a comment containing the CrowdStrike incident/alert ID. JIRA automation must then parse this comment and set a custom field (e.g., `cs_incident_id` or `cs_alert_id`) in the issue. This script uses that custom field to link the CrowdStrike record to the JIRA issue and subsequently synchronizes comments, status, and assignee information.

> **IMPORTANT:**  
**USE AT YOUR OWN RISK. NO WARRANTIES OR GUARANTEES ARE PROVIDED.**  
> It is your responsibility to test and validate this script in your environment.

## Prerequisites

### Software Requirements

- **Python 3.x**

### Python Packages

Install the required Python packages with:

```bash
pip install crowdstrike-falconpy jira pyyaml python-json-logger
```

## Permissions and Environment Variables

Before running the script, ensure you have set up the following environment variables with the appropriate permissions:

- **For CrowdStrike:**
  - `CS_CLIENT_ID`  
  - `CS_CLIENT_SECRET`  
  These credentials must have read/write permissions to incidents, alerts, and detections in your CrowdStrike environment.

- **For JIRA:**
  - `JIRA_SERVER`  
  - `JIRA_USERNAME`  
  - `JIRA_API_TOKEN`  
  These credentials must have read and write permissions to the JIRA project you wish to synchronize.

## Configuration

The script uses a YAML configuration file (`sync_config.yaml`) to determine key settings. Below is an example configuration:

```yaml
# sync_config.yaml

jira_project_key: "your_jira_project_key" # Jira project key

custom_fields:
  incident:
    display_name: "your_jira_custom_incident_name_field" # Custom field name in Jira for incident IDs
    field_id: "your_jira_custom_incident_ID_field"          # Custom field ID in Jira for incident IDs
  alert:
    display_name: "your_jira_custom_alert_name_field"        # Custom field name in Jira for alert IDs
    field_id: "your_jira_custom_alert_name_field"            # Custom field ID in Jira for alert IDs

jira_status_mapping_incidents:
  new: 20
  reopened: 25
  in progress: 30
  done: 40

jira_status_mapping_alerts:
  ignored: "ignored"
  new: "new"
  in progress: "in_progress"
  true positive: "true_positive"
  false positive: "false_positive"

open_statuses:
  - "To Do"
  - "In Progress"
  - "Reopened"

sync_options:
  sync_status: true
  sync_assignee: true
  sync_comments: true
  sync_comments_for_closed: false

# Jira UUID to CrowdStrike (Cortex) UUID mapping
jira_to_cs_user_map:
  "jira_user_1": "cs_user_uuid_1"
  "jira_user_2": "cs_user_uuid_2"

max_workers: 5
max_retries: 5
backoff_factor: 2
poll_interval: 60
```

### Important Configuration Notes

- **Custom Fields:**  
  - Update the `custom_fields` section with your JIRA project’s custom field names and IDs that will store the CrowdStrike incident or alert IDs.
  
- **User Mapping:**  
  - The `jira_to_cs_user_map` provides the mapping between your JIRA user IDs and CrowdStrike user UUIDs.  
  **Ensure that these mappings reflect your environment.**

- **Sync Options:**  
  - The `sync_options.sync_comments_for_closed` flag controls whether comments are synced for closed issues.  
    Set it to `false` to stop syncing comments for closed issues, which is the recommended setting for most workflows.

## How It Works

1. **SOAR Workflow Integration:**  
   The CrowdStrike SOAR workflow creates a JIRA issue (incident or alert) and appends a comment containing the CrowdStrike ID.

2. **JIRA Automation:**  
   You must create JIRA automation rules that trigger upon the comment being added and parse the CrowdStrike ID from the comment. This parsed ID is then set on a custom field in the issue.

3. **Script Processing:**  
   The script:
   - Loads configuration and dynamically reloads it if it changes.
   - Reads the custom fields in the JIRA issues to identify the corresponding CrowdStrike incident/alert.
   - Syncs comments, status, and assignee data (if enabled) between JIRA and CrowdStrike.
   - Supports options such as not syncing comments for closed issues (controlled by `sync_comments_for_closed`).

## Running the Script

1. **Set up your environment variables** for CrowdStrike and JIRA credentials.
2. **Configure the `sync_config.yaml` file** according to your environment (adjust project key, custom field names/IDs, user mappings, etc.).
3. Run the script:

   ```bash
   python3 jira_cs_sync.py
   ```

## Disclaimer

**THIS SCRIPT IS PROVIDED "AS-IS" WITHOUT ANY WARRANTIES OR GUARANTEES.**  
The script depends on you having the proper environment variables, permissions, and correct user mappings as per your environment.  
Use it at your own risk. The author and maintainers are not responsible for any issues, data loss, or unintended consequences resulting from its use.

## License

This project is distributed without any warranties. Use at your own risk.
