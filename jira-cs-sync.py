#!/usr/bin/env python3
"""
JIRA <-> CrowdStrike Sync Script
================================

Overview:
---------
This script synchronizes CrowdStrike incident and alert data with a JIRA Cloud project. It works with the 
CrowdStrike SOAR JIRA plugin (install via pip install crowdstrike-falconpy).The SOAR workflow in CrowdStrike 
creates an incident or alert as a JIRA issue and appends a comment that includes the corresponding CrowdStrike 
incident/alert ID. JIRA automation must be used to parse this ID and set it as a custom field (one for incident 
ID and one for alert ID) in the issue. This script then uses that custom field to relate the CrowdStrike record 
to the JIRA issue, synchronizing comments, status, and assignee information.

Requirements:
-------------
- **JIRA**: JIRA Cloud with permissions (read and write) for your project.
- **CrowdStrike**: Required permissions to read/write incidents, alerts, and detections.
- **Environment Variables**: You must set the following:
    - For CrowdStrike:
        - CS_CLIENT_ID
        - CS_CLIENT_SECRET
    - For JIRA:
        - JIRA_SERVER
        - JIRA_USERNAME
        - JIRA_API_TOKEN
- **User Mapping**: In the YAML configuration (sync_config.yaml), the keys (e.g., "jira_user_1") and corresponding 
  values (e.g., "cs_user_uuid_1") represent your environment's user identifiers. **You must adjust these mappings** 
  to match your environment.

Disclaimer:
-----------
It is provided "AS IS" without any warranties or guarantees whatsoever. Use it at your own risk.

Usage:
------
- Configure your sync_config.yaml.
- Set the required environment variables.
- Run the script: `python3 jira_cs_sync.py`

Maintenance:
------------
- The script includes dynamic configuration reload – changes to the YAML config will trigger a reload on each cycle.
- Logs are written in JSON format with log rotation for long-term operation.
- Detailed error handling and retry mechanisms are in place.
- Signals (SIGTERM and SIGINT) are caught to allow for graceful shutdown.
"""

import os
import sys
import json
import logging
import time
import signal
import hashlib
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from requests.exceptions import HTTPError
import yaml
from pythonjsonlogger import jsonlogger
from falconpy import OAuth2, Incidents, Alerts, UserManagement
from jira import JIRA, JIRAError

###############################################################################
# CONFIG & LOGGING SETUP
###############################################################################
# Set up logger with JSON formatting for both console and file handlers.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Console handler (logs in JSON format)
console_handler = logging.StreamHandler(sys.stdout)
console_formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# Rotating file handler (rotates at 5 MB, 5 backup files)
LOG_FILE = "jira-cs-sync.log"
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
file_formatter = jsonlogger.JsonFormatter('%(asctime)s [%(levelname)s] %(message)s', 
                                           datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(file_formatter)
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

###############################################################################
# CONFIGURATION LOADING & DYNAMIC RELOAD
###############################################################################
CONFIG_FILE = "sync_config.yaml"
CONFIG_MTIME = None  # Track config file modification time

def load_config(config_file=CONFIG_FILE):
    """Load configuration from the YAML file."""
    if not os.path.exists(config_file):
        logger.error(f"Configuration file '{config_file}' not found. Exiting.")
        sys.exit(1)
    try:
        logger.info(f"Loading configuration from {config_file} ...")
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)
        logger.info("Configuration loaded successfully from YAML.")
        return config
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error in '{config_file}': {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading configuration file '{config_file}': {e}")
        sys.exit(1)

def validate_required_config(config):
    """Ensure that all required config keys are present."""
    required_keys = ["jira_project_key", "custom_fields", "poll_interval"]
    missing = [k for k in required_keys if k not in config]
    if missing:
        logger.error(f"Missing required config keys in {CONFIG_FILE}: {', '.join(missing)}")
        sys.exit(1)

def reload_config_if_modified():
    """Reload configuration if the file has been modified."""
    global CONFIG, CONFIG_MTIME
    try:
        mtime = os.path.getmtime(CONFIG_FILE)
        if CONFIG_MTIME is None or mtime > CONFIG_MTIME:
            CONFIG = load_config(CONFIG_FILE)
            validate_required_config(CONFIG)
            logger.info("Configuration reloaded due to changes in the config file.")
            CONFIG_MTIME = mtime
    except Exception as e:
        logger.error(f"Error reloading configuration: {e}")

# Initial config load
CONFIG = load_config()
validate_required_config(CONFIG)

# Extract configuration parameters
# Update the global variables with the configuration values
# Update to match your Jira project infomration 
POLL_INTERVAL = CONFIG["poll_interval"]
STATE_FILE = CONFIG.get("state_file", "sync_state.json")
JIRA_PROJECT_KEY = CONFIG.get("jira_project_key", "your_jira_project_key") # Jira project key
CUSTOM_FIELDS = CONFIG.get("custom_fields", {})
CS_INCIDENT_DISPLAY_NAME = CUSTOM_FIELDS.get("incident", {}).get("display_name", "your_jira_custom_incident_name_field") # Custom Incidnet field name in Jira
CS_INCIDENT_FIELD_ID = CUSTOM_FIELDS.get("incident", {}).get("field_id", "your_jira_custom_incident_ID_field") # Custom Incident field ID in Jira
CS_ALERT_DISPLAY_NAME = CUSTOM_FIELDS.get("alert", {}).get("display_name", "your_jira_custom_alert_name_field") # Custom alert field name in Jira
CS_ALERT_FIELD_ID = CUSTOM_FIELDS.get("alert", {}).get("field_id", "your_jira_custom_alert_name_field") # Custom alert field ID in Jira
JIRA_STATUS_MAPPING_INCIDENTS = CONFIG.get("jira_status_mapping_incidents", {})
JIRA_STATUS_MAPPING_ALERTS = CONFIG.get("jira_status_mapping_alerts", {})
OPEN_JIRA_STATUSES = [status.lower() for status in CONFIG.get("open_statuses", [])]
JIRA_TO_CS_USER_MAP = CONFIG.get("jira_to_cs_user_map", {})
CS_TO_JIRA_USER_MAP = {v: k for k, v in JIRA_TO_CS_USER_MAP.items()}
MAX_WORKERS = CONFIG.get("max_workers", 5)
MAX_RETRIES = CONFIG.get("max_retries", 5)
BACKOFF_FACTOR = CONFIG.get("backoff_factor", 2)
SYNC_OPTIONS = CONFIG.get("sync_options", {
    "sync_status": True,
    "sync_assignee": True,
    "sync_comments": True,
    "sync_comments_for_closed": False
})

###############################################################################
# AUTHENTICATION FUNCTIONS
###############################################################################
def get_cs_auth():
    """
    Authenticate to CrowdStrike using OAuth2.
    Requires CS_CLIENT_ID and CS_CLIENT_SECRET environment variables.
    """
    missing_env = []
    if "CS_CLIENT_ID" not in os.environ:
        missing_env.append("CS_CLIENT_ID")
    if "CS_CLIENT_SECRET" not in os.environ:
        missing_env.append("CS_CLIENT_SECRET")
    if missing_env:
        logger.error(f"Missing CrowdStrike env variables: {', '.join(missing_env)}")
        sys.exit(1)
    try:
        logger.info("Authenticating to CrowdStrike API using OAuth2 credentials...")
        return OAuth2(client_id=os.environ["CS_CLIENT_ID"], client_secret=os.environ["CS_CLIENT_SECRET"])
    except Exception as e:
        logger.error(f"Error during CrowdStrike authentication: {e}")
        sys.exit(1)

def get_cs_clients():
    """
    Initialize and return CrowdStrike API clients for Incidents, Alerts,
    and UserManagement.
    """
    logger.info("Initializing FalconPy clients (Incidents, Alerts, UserManagement)...")
    try:
        auth = get_cs_auth()
        incidents_client = Incidents(auth_object=auth)
        alerts_client = Alerts(auth_object=auth)
        users_client = UserManagement(auth_object=auth)
        logger.info("CrowdStrike clients initialized successfully.")
        return {"incidents": incidents_client, "alerts": alerts_client, "users": users_client}
    except Exception as e:
        logger.error(f"Error initializing CrowdStrike clients: {e}")
        sys.exit(1)

def get_jira_client():
    """
    Initialize and return a JIRA client.
    Requires JIRA_SERVER, JIRA_USERNAME, and JIRA_API_TOKEN environment variables.
    """
    missing_env = []
    if "JIRA_SERVER" not in os.environ:
        missing_env.append("JIRA_SERVER")
    if "JIRA_USERNAME" not in os.environ:
        missing_env.append("JIRA_USERNAME")
    if "JIRA_API_TOKEN" not in os.environ:
        missing_env.append("JIRA_API_TOKEN")
    if missing_env:
        logger.error(f"Missing Jira env variables: {', '.join(missing_env)}")
        sys.exit(1)
    try:
        logger.info("Connecting to Jira...")
        jira = JIRA(server=os.environ["JIRA_SERVER"],
                    basic_auth=(os.environ["JIRA_USERNAME"], os.environ["JIRA_API_TOKEN"]))
        logger.info("Connected to Jira successfully.")
        return jira
    except Exception as e:
        logger.error(f"Error initializing Jira client: {e}")
        sys.exit(1)

# --- Wrapper functions for ease-of-use:
def get_cs_authentication():
    return get_cs_auth()

def get_cs_clients_wrapper():
    return get_cs_clients()

def get_jira_client_wrapper():
    return get_jira_client()

###############################################################################
# STATE MANAGEMENT (Using JSON file)
###############################################################################
def load_state():
    """Load the sync state from a JSON file."""
    if os.path.exists(STATE_FILE):
        try:
            logger.info(f"Loading sync state from {STATE_FILE} ...")
            with open(STATE_FILE, "r") as f:
                raw_state = json.load(f)
            state = {}
            for resource_id, stored_data in raw_state.items():
                comments = stored_data.get("comments", {})
                state[resource_id] = {
                    "comments": {"jira_to_cs": set(comments.get("jira_to_cs", [])),
                                 "cs_to_jira": set(comments.get("cs_to_jira", []))},
                    "assigned": stored_data.get("assigned"),
                    "status": stored_data.get("status"),
                    "last_jira_status": stored_data.get("last_jira_status")
                }
            logger.debug("State loaded successfully from file.")
            return state
        except Exception as e:
            logger.error(f"Error loading state: {e}")
            return {}
    else:
        logger.info("No state file found, starting fresh.")
        return {}

def save_state(state):
    """Save the current sync state to a JSON file."""
    try:
        logger.info("Saving current sync state to file...")
        serializable = {}
        for resource_id, data in state.items():
            serializable[resource_id] = {
                "comments": {"jira_to_cs": list(data["comments"]["jira_to_cs"]),
                             "cs_to_jira": list(data["comments"]["cs_to_jira"])},
                "assigned": data.get("assigned"),
                "status": data.get("status"),
                "last_jira_status": data.get("last_jira_status")
            }
        with open(STATE_FILE, "w") as f:
            json.dump(serializable, f, indent=4)
        logger.debug("State saved successfully.")
    except Exception as e:
        logger.error(f"Error saving state: {e}")

###############################################################################
# HELPER FUNCTIONS
###############################################################################
def hash_comment(content):
    """Return the SHA256 hash of a comment's content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def parse_cs_timestamp(timestamp):
    """Parse a CrowdStrike timestamp into a Python datetime object."""
    try:
        if "." in timestamp:
            timestamp = timestamp.split(".")[0] + "Z"
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception as e:
        logger.error(f"Error parsing timestamp '{timestamp}': {e}")
        return datetime.now(timezone.utc)

def get_jira_assignee_id(jira_issue):
    """Return the accountId of the Jira issue assignee (if available)."""
    try:
        return jira_issue.fields.assignee.accountId if jira_issue.fields.assignee else None
    except Exception as e:
        logger.error(f"Error getting Jira assignee: {e}")
        return None

def parse_response(response):
    """Parse the API response and return a dictionary."""
    logger.debug(f"Parsing response. Type: {type(response)}, Content: {response}")
    try:
        if isinstance(response, str):
            return json.loads(response)
        elif isinstance(response, dict):
            return response
        else:
            logger.error(f"Unexpected response type: {type(response)}")
            return {}
    except Exception as e:
        logger.error(f"Error parsing response: {e}")
        return {}

###############################################################################
# INCIDENT ACTIONS - Uber Style
###############################################################################
def perform_incident_action_direct(cs_client, payload, update_detects=False, overwrite_detects=False, max_retries=5, backoff_factor=2):
    """
    Executes a CrowdStrike incident action (e.g., add comment, update status) using the Uber command.
    Retries with exponential backoff on rate limiting (HTTP 429).
    """
    attempts = 0
    ud_str = "true" if update_detects else "false"
    od_str = "true" if overwrite_detects else "false"
    while attempts < max_retries:
        try:
            logger.debug(f"Attempt {attempts+1} for PerformIncidentAction with payload={payload}")
            response = cs_client.command("PerformIncidentAction",
                                         body=payload,
                                         update_detects=ud_str,
                                         overwrite_detects=od_str)
            parsed = parse_response(response)
            if parsed.get("status_code") == 429:
                raise HTTPError(response=response)
            return parsed
        except HTTPError as e:
            if e.response and e.response.status_code == 429:
                sleep_time = backoff_factor ** attempts
                logger.warning(f"Rate limited on PerformIncidentAction. Sleeping {sleep_time} seconds...")
                time.sleep(sleep_time)
                attempts += 1
            else:
                logger.error(f"HTTP error in PerformIncidentAction: {e}")
                break
        except Exception as e:
            logger.error(f"Unexpected error in PerformIncidentAction: {e}")
            break
    logger.error(f"Max retries exceeded for payload={payload}.")
    return None

###############################################################################
# ALERT ACTIONS - Uber Style
###############################################################################
def update_alerts_v3_direct(cs_client, payload, max_retries=5, backoff_factor=2):
    """
    Executes a CrowdStrike alert action (e.g., append comment, update status) using the Uber API.
    Retries with exponential backoff on rate limiting.
    """
    attempts = 0
    while attempts < max_retries:
        try:
            logger.debug(f"Attempt {attempts+1} for update_alerts_v3 with payload={payload}")
            response = cs_client.update_alerts_v3(body=payload, parameters={"include_hidden": "true"})
            parsed = parse_response(response)
            if parsed.get("status_code") == 429:
                raise HTTPError(response=response)
            return parsed
        except HTTPError as e:
            if e.response and e.response.status_code == 429:
                sleep_time = backoff_factor ** attempts
                logger.warning(f"Rate limited on update_alerts_v3. Sleeping {sleep_time} seconds...")
                time.sleep(sleep_time)
                attempts += 1
            else:
                logger.error(f"HTTP error in update_alerts_v3: {e}")
                break
        except Exception as e:
            logger.error(f"Unexpected error in update_alerts_v3: {e}")
            break
    logger.error(f"Max retries exceeded for payload={payload}.")
    return None

###############################################################################
# USER MAPPING FUNCTIONS
###############################################################################
def retrieve_user_uuid(cs_clients, jira_user_id):
    """
    Maps a Jira user to a CrowdStrike user UUID using the provided configuration mapping.
    """
    try:
        cs_user_uuid = JIRA_TO_CS_USER_MAP.get(jira_user_id)
        if cs_user_uuid:
            logger.info(f"Mapped Jira user '{jira_user_id}' to CS UUID '{cs_user_uuid}'.")
            users_client = cs_clients["users"]
            response = users_client.retrieve_user(ids=[cs_user_uuid])
            parsed = parse_response(response)
            if parsed.get("status_code") == 200 and parsed.get("body", {}).get("resources"):
                return cs_user_uuid
            else:
                logger.warning(f"CS user '{cs_user_uuid}' does not exist or is inaccessible.")
                return None
        else:
            logger.warning(f"No CS mapping for Jira user '{jira_user_id}'.")
            return None
    except Exception as e:
        logger.error(f"Error retrieving CS UUID for Jira user '{jira_user_id}': {e}")
        return None

def validate_user_mapping(jira_client, cs_clients, jira_user_id, cs_user_id):
    """
    Validates that the Jira user exists and that the CrowdStrike user UUID is valid.
    """
    try:
        jira_user = jira_client.user(jira_user_id)
        if not jira_user:
            logger.warning(f"Jira user '{jira_user_id}' does not exist.")
            return False
    except Exception as e:
        logger.error(f"Error validating Jira user '{jira_user_id}': {e}")
        return False
    try:
        users_client = cs_clients["users"]
        response = users_client.retrieve_user(ids=[cs_user_id])
        parsed = parse_response(response)
        if parsed.get("status_code") == 200 and parsed.get("body", {}).get("resources"):
            return True
        else:
            logger.warning(f"CS user '{cs_user_id}' does not exist.")
            return False
    except Exception as e:
        logger.error(f"Error validating CS user '{cs_user_id}': {e}")
        return False

def get_cs_user_mapping(jira_client, cs_clients, mapping):
    """
    Returns a mapping of Jira user IDs to CrowdStrike user UUIDs
    based on the configuration.
    """
    valid_map = {}
    for jira_user_id, cs_user_id in mapping.items():
        if validate_user_mapping(jira_client, cs_clients, jira_user_id, cs_user_id):
            cs_uuid = retrieve_user_uuid(cs_clients, jira_user_id)
            if cs_uuid:
                valid_map[jira_user_id] = cs_uuid
        else:
            logger.warning(f"Invalid mapping: Jira '{jira_user_id}' -> CS '{cs_user_id}'")
    return valid_map

def validate_user_mappings(jira_client, cs_clients, config):
    """
    Validate and return a complete mapping of Jira users to CrowdStrike user UUIDs.
    """
    mapping = config.get("jira_to_cs_user_map", {})
    if not mapping:
        logger.warning("No Jira-to-CS user mappings found in config.")
        return {}
    valid_map = get_cs_user_mapping(jira_client, cs_clients, mapping)
    if not valid_map:
        logger.warning("No valid user mappings after validation.")
    else:
        logger.info(f"Validated {len(valid_map)} user mappings between Jira and CS.")
    return valid_map

###############################################################################
# SYNC COMMENTS
###############################################################################
def sync_comments(jira_client, jira_issue, cs_client, cs_item, state, issue_type, orig_cs_id=None):
    """
    Sync comments from Jira to CrowdStrike.
    - Incidents: Uses 'add_comment' via PerformIncidentAction.
    - Alerts: Uses 'append_comment' via update_alerts_v3_direct.
    If orig_cs_id is provided (for alerts), it is used to pass the full composite ID.
    Duplicate comments (based on hash) are skipped.
    Additionally, if the issue is closed and the config option 'sync_comments_for_closed' 
    is False, comment syncing is skipped.
    """
    try:
        if issue_type.lower() == "incident":
            cs_id = cs_item.get("incident_id")
        else:
            cs_id = orig_cs_id if orig_cs_id else cs_item.get("id")
        if not cs_id:
            logger.error(f"No CS ID found in {issue_type} data: {cs_item}")
            return

        # Check if we should sync comments for closed issues.
        jira_status = jira_issue.fields.status.name.lower()
        if jira_status not in OPEN_JIRA_STATUSES and not SYNC_OPTIONS.get("sync_comments_for_closed", False):
            logger.info(f"Issue {jira_issue.key} is closed and comment sync is disabled for closed issues. Skipping comment sync.")
            return

        item_state = state.get(cs_id, {
            "comments": {"jira_to_cs": set(), "cs_to_jira": set()},
            "assigned": None,
            "status": None,
            "last_jira_status": None
        })
        existing_hashes = item_state["comments"]["jira_to_cs"]
        jira_comments = {hash_comment(c.body.strip()): c.body.strip() 
                         for c in jira_issue.fields.comment.comments}

        if SYNC_OPTIONS.get("sync_comments", False):
            if issue_type.lower() == "incident":
                for h, text in jira_comments.items():
                    if h in existing_hashes:
                        logger.debug(f"Incident {cs_id} comment with hash {h} already synced. Skipping.")
                        continue
                    logger.info(f"Adding Jira comment to CS incident {cs_id}: {text}")
                    payload = {"action_parameters": [{"name": "add_comment", "value": text}],
                               "ids": [cs_id]}
                    response = perform_incident_action_direct(cs_client, payload)
                    if response and response.get("status_code") == 200:
                        logger.debug(f"Comment added to incident {cs_id}.")
                        existing_hashes.add(h)
                    else:
                        logger.warning(f"Failed to add comment to incident {cs_id}: {response}")
            elif issue_type.lower() == "alert":
                for h, text in jira_comments.items():
                    if h in existing_hashes:
                        logger.debug(f"Alert {cs_id} comment with hash {h} already synced. Skipping.")
                        continue
                    logger.info(f"Appending Jira comment to CS alert {cs_id}: {text}")
                    payload = {
                        "composite_ids": [cs_id],
                        "action_parameters": [{"name": "append_comment", "value": text}]
                    }
                    response = update_alerts_v3_direct(cs_client, payload)
                    if response and response.get("status_code") in [200, 201]:
                        logger.debug(f"Comment appended to alert {cs_id}.")
                        existing_hashes.add(h)
                    else:
                        logger.warning(f"Failed to append comment to alert {cs_id}: {response}")
        item_state["comments"]["jira_to_cs"] = existing_hashes
        state[cs_id] = item_state

    except Exception as e:
        logger.error(f"Error syncing comments for {issue_type} {cs_id} in Jira issue {jira_issue.key}: {e}")

###############################################################################
# SYNC STATUS
###############################################################################
def sync_status(jira_issue, cs_client, cs_item, state, cs_id, issue_type):
    """
    Sync the status from Jira to CrowdStrike.
    Only updates if the status in Jira is different from what is stored in the state.
    """
    if not SYNC_OPTIONS.get("sync_status", False):
        logger.debug("Status sync is disabled. Skipping.")
        return
    try:
        jira_status = jira_issue.fields.status.name.lower()
        item_state = state.get(cs_id, {"comments": {"jira_to_cs": set(), "cs_to_jira": set()},
                                        "assigned": None, "status": None, "last_jira_status": None})
        if item_state.get("last_jira_status") == jira_status:
            logger.info(f"[SKIP] {issue_type.capitalize()} {cs_id} status already '{jira_status}'.")
            return
        if issue_type.lower() == "incident":
            desired_status = JIRA_STATUS_MAPPING_INCIDENTS.get(jira_status)
            if desired_status is None:
                logger.warning(f"No numeric mapping for Jira status '{jira_status}' in {jira_issue.key}.")
                item_state["last_jira_status"] = jira_status
                state[cs_id] = item_state
                return
            current_status = cs_item.get("status_code")
            if str(current_status) == str(desired_status):
                logger.info(f"[SKIP] Incident {cs_id} already status {desired_status}.")
                item_state["last_jira_status"] = jira_status
                state[cs_id] = item_state
                return
            logger.info(f"Updating incident {cs_id} from {current_status} to {desired_status} (Jira {jira_issue.key}).")
            payload = {"action_parameters": [{"name": "update_status", "value": str(desired_status)}],
                       "ids": [cs_id]}
            response = perform_incident_action_direct(cs_client, payload)
            if response and response.get("status_code") == 200:
                logger.debug(f"Incident {cs_id} status updated to {desired_status}.")
                item_state["status"] = desired_status
                item_state["last_jira_status"] = jira_status
            else:
                logger.error(f"Failed to update status for incident {cs_id}: {response}")
        elif issue_type.lower() == "alert":
            desired_status = JIRA_STATUS_MAPPING_ALERTS.get(jira_status)
            if desired_status is None:
                logger.warning(f"No valid mapping for Jira status '{jira_status}' in {jira_issue.key}.")
                item_state["last_jira_status"] = jira_status
                state[cs_id] = item_state
                return
            logger.info(f"Updating alert {cs_id} to '{desired_status}' (Jira {jira_issue.key}).")
            payload = {"composite_ids": [cs_id],
                       "action_parameters": [{"name": "update_status", "value": desired_status}]}
            response = update_alerts_v3_direct(cs_client, payload)
            if response and response.get("status_code") in [200, 201]:
                logger.debug(f"Alert {cs_id} status updated to '{desired_status}'.")
                item_state["status"] = desired_status
                item_state["last_jira_status"] = jira_status
            else:
                logger.error(f"Failed to update status for alert {cs_id}: {response}")
        else:
            logger.error(f"Unknown issue type '{issue_type}' for status sync.")
        state[cs_id] = item_state
    except Exception as e:
        logger.error(f"Error syncing status for {jira_issue.key} (CS {cs_id}, {issue_type}): {e}")

###############################################################################
# SYNC ASSIGNEE
###############################################################################
def sync_assignee(jira_issue, cs_client, cs_item, state, cs_id, user_map, issue_type):
    """
    Sync the assignee from Jira to CrowdStrike.
    Uses a mapping defined in the configuration to convert Jira users to CrowdStrike UUIDs.
    """
    if not SYNC_OPTIONS.get("sync_assignee", False):
        logger.debug("Assignee sync is disabled. Skipping.")
        return
    try:
        jira_assignee = get_jira_assignee_id(jira_issue)
        item_state = state.get(cs_id, {"comments": {"jira_to_cs": set(), "cs_to_jira": set()},
                                        "assigned": None, "status": None, "last_jira_status": None})
        if jira_assignee == item_state.get("assigned"):
            logger.debug(f"[SKIP] {issue_type.capitalize()} {cs_id} already assigned to Jira user {jira_assignee}.")
            return
        if jira_assignee:
            cs_assignee = user_map.get(jira_assignee)
            if not cs_assignee:
                logger.warning(f"No CS mapping for Jira user '{jira_assignee}' in {jira_issue.key}.")
                return
            if issue_type.lower() == "incident":
                logger.info(f"Assigning incident {cs_id} to CS user UUID '{cs_assignee}' (Jira {jira_issue.key}).")
                payload = {"action_parameters": [{"name": "update_assigned_to_v2", "value": cs_assignee}],
                           "ids": [cs_id]}
                response = perform_incident_action_direct(cs_client, payload)
                if response and response.get("status_code") == 200:
                    logger.debug(f"Incident {cs_id} assigned to '{cs_assignee}'.")
                    item_state["assigned"] = jira_assignee
                else:
                    logger.error(f"Failed to assign incident {cs_id}: {response}")
            elif issue_type.lower() == "alert":
                logger.info(f"Assigning alert {cs_id} to CS user UUID '{cs_assignee}' (Jira {jira_issue.key}).")
                payload = {"composite_ids": [cs_id],
                           "action_parameters": [{"name": "assign_to_uuid", "value": cs_assignee}]}
                response = update_alerts_v3_direct(cs_client, payload)
                if response and response.get("status_code") in [200, 201]:
                    logger.debug(f"Alert {cs_id} assigned to '{cs_assignee}'.")
                    item_state["assigned"] = jira_assignee
                else:
                    logger.error(f"Failed to assign alert {cs_id}: {response}")
            else:
                logger.error(f"Unknown issue type '{issue_type}' in {jira_issue.key}.")
        else:
            logger.info(f"Removing assignee from CS {issue_type} {cs_id} (Jira {jira_issue.key}).")
            if issue_type.lower() == "incident":
                payload = {"action_parameters": [{"name": "unassign", "value": "true"}],
                           "ids": [cs_id]}
                response = perform_incident_action_direct(cs_client, payload)
                if response and response.get("status_code") == 200:
                    logger.debug(f"Incident {cs_id} unassigned.")
                    item_state["assigned"] = None
                else:
                    logger.error(f"Failed to unassign incident {cs_id}: {response}")
            elif issue_type.lower() == "alert":
                payload = {"composite_ids": [cs_id],
                           "action_parameters": [{"name": "unassign", "value": "true"}]}
                response = update_alerts_v3_direct(cs_client, payload)
                if response and response.get("status_code") in [200, 201]:
                    logger.debug(f"Alert {cs_id} unassigned.")
                    item_state["assigned"] = None
                else:
                    logger.error(f"Failed to unassign alert {cs_id}: {response}")
            else:
                logger.error(f"Unknown issue type '{issue_type}' in {jira_issue.key}.")
        state[cs_id] = item_state
    except Exception as e:
        logger.error(f"Error syncing assignee for {jira_issue.key} (CS {cs_id}, {issue_type}): {e}")

###############################################################################
# PER-ISSUE PROCESSING
###############################################################################
def process_incident(jira_client, cs_clients, jira_issue, state, user_map, issue_type):
    """
    Process a single Jira issue:
      - Extracts the CrowdStrike ID from a custom field.
      - For alerts, the composite ID is preserved in full.
      - Based on sync options and issue status, calls functions to sync comments,
        status, and assignee.
    """
    try:
        if issue_type.lower() == "incident":
            cs_id = getattr(jira_issue.fields, CS_INCIDENT_FIELD_ID, None)
        elif issue_type.lower() == "alert":
            cs_id = getattr(jira_issue.fields, CS_ALERT_FIELD_ID, None)
        else:
            logger.error(f"Unknown issue type: {issue_type} for Jira {jira_issue.key}")
            return
        if not cs_id:
            logger.warning(f"No CS ID found in Jira issue {jira_issue.key} for {issue_type}. Skipping.")
            return
        if issue_type.lower() == "alert":
            # Do NOT split the composite ID; use the full value.
            cs_ids = [cs_id.strip()] if isinstance(cs_id, str) else cs_id
        else:
            cs_ids = [x.strip() for x in cs_id.split(",")] if isinstance(cs_id, str) else cs_id

        for single_cs_id in cs_ids:
            logger.info(f"Processing {issue_type.capitalize()} CS ID '{single_cs_id}' for Jira issue {jira_issue.key}.")
            if issue_type.lower() == "incident":
                resp = cs_clients["incidents"].get_incidents(ids=[single_cs_id])
            else:
                resp = cs_clients["alerts"].get_alerts(ids=[single_cs_id])
            parsed = parse_response(resp)
            if parsed.get("status_code") != 200:
                logger.error(f"Failed to fetch {issue_type} {single_cs_id} for {jira_issue.key}: {parsed}")
                continue
            resources = parsed.get("body", {}).get("resources", [])
            if not resources:
                logger.error(f"No resources for {issue_type} {single_cs_id} (Jira {jira_issue.key}).")
                continue
            cs_item = resources[0]
            jira_status = jira_issue.fields.status.name.lower()
            # Proceed if the issue is open or if syncing for closed issues is enabled.
            if jira_status in OPEN_JIRA_STATUSES or SYNC_OPTIONS.get("sync_comments_for_closed", False):
                logger.debug(f"Jira {jira_issue.key} status is '{jira_issue.fields.status.name}'. Proceeding for CS {issue_type} {single_cs_id}.")
                if SYNC_OPTIONS.get("sync_comments", False):
                    if issue_type.lower() == "alert":
                        # Pass the full composite ID as provided.
                        sync_comments(jira_client, jira_issue, cs_clients["alerts"], cs_item, state, issue_type, orig_cs_id=single_cs_id)
                    else:
                        sync_comments(jira_client, jira_issue, cs_clients["incidents"], cs_item, state, issue_type)
                if SYNC_OPTIONS.get("sync_status", False):
                    sync_status(jira_issue,
                              cs_clients["incidents"] if issue_type.lower() == "incident" else cs_clients["alerts"],
                              cs_item, state, single_cs_id, issue_type)
                if SYNC_OPTIONS.get("sync_assignee", False):
                    sync_assignee(jira_issue,
                              cs_clients["incidents"] if issue_type.lower() == "incident" else cs_clients["alerts"],
                              cs_item, state, single_cs_id, user_map, issue_type)
            else:
                logger.info(f"Jira {jira_issue.key} for {issue_type} {single_cs_id} is not open (status '{jira_issue.fields.status.name}'). Skipping.")
    except Exception as e:
        logger.error(f"Error processing Jira issue {jira_issue.key} for {issue_type}: {e}")

###############################################################################
# MAIN SYNC LOOP
###############################################################################
def sync_jira_and_crowdstrike(jira_client, cs_clients, user_map):
    """
    Main synchronization loop:
      - Dynamically reloads configuration if modified.
      - Loads current sync state.
      - Queries Jira for issues with custom fields set.
      - Processes incidents and alerts concurrently.
      - Saves updated sync state.
    """
    try:
        reload_config_if_modified()
        state = load_state()
        logger.info("Querying Jira for Incidents and Alerts...")
        jql_incidents = f'"{CS_INCIDENT_DISPLAY_NAME}" IS NOT EMPTY AND project = "{JIRA_PROJECT_KEY}"'
        jql_alerts = f'"{CS_ALERT_DISPLAY_NAME}" IS NOT EMPTY AND project = "{JIRA_PROJECT_KEY}"'
        try:
            incidents = jira_client.search_issues(jql_incidents, maxResults=1000)
            alerts = jira_client.search_issues(jql_alerts, maxResults=1000)
            logger.info(f"Fetched {len(incidents)} incidents and {len(alerts)} alerts from Jira.")
        except JIRAError as e:
            logger.error(f"JiraError during issue fetching: {e}")
            incidents, alerts = [], []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures_incidents = [executor.submit(process_incident, jira_client, cs_clients, issue, state, user_map, "incident")
                                  for issue in incidents]
            for future in as_completed(futures_incidents):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in incident thread: {e}")
            futures_alerts = [executor.submit(process_incident, jira_client, cs_clients, issue, state, user_map, "alert")
                              for issue in alerts]
            for future in as_completed(futures_alerts):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in alert thread: {e}")
        save_state(state)
    except Exception as e:
        logger.error(f"Error syncing Jira and CrowdStrike: {e}")
        print(f"[ERROR] An unexpected error occurred: {e}")

###############################################################################
# VALIDATION FUNCTIONS
###############################################################################
def validate_jira_fields(jira_client, config):
    """
    Validate that required JIRA custom fields (set in the configuration) exist.
    """
    try:
        fields = jira_client.fields()
        field_names = {f["name"]: f["id"] for f in fields}
        inc_field = config["custom_fields"]["incident"]["display_name"]
        alert_field = config["custom_fields"]["alert"]["display_name"]
        if inc_field not in field_names:
            logger.error(f"Jira custom field '{inc_field}' not found.")
            sys.exit(1)
        if alert_field not in field_names:
            logger.error(f"Jira custom field '{alert_field}' not found.")
            sys.exit(1)
        logger.info("Jira custom fields validated successfully.")
    except Exception as e:
        logger.error(f"Error validating Jira fields: {e}")
        sys.exit(1)

def test_jira_connectivity(jira_client):
    """
    Test connectivity to JIRA by fetching one issue.
    """
    try:
        sample = jira_client.search_issues(f'project = "{JIRA_PROJECT_KEY}"', maxResults=1)
        if sample:
            logger.info("Jira connectivity test successful.")
            return True
        else:
            logger.warning("No issues found in Jira project.")
            return False
    except Exception as e:
        logger.error(f"Error testing Jira connectivity: {e}")
        return False

###############################################################################
# SIGNAL HANDLING FOR GRACEFUL SHUTDOWN
###############################################################################
def handle_shutdown(signum, frame):
    logger.info("Shutdown signal received. Exiting gracefully.")
    save_state({})
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_shutdown)
signal.signal(signal.SIGINT, handle_shutdown)

###############################################################################
# MAIN ENTRY POINT
###############################################################################
def main():
    print("Starting Jira <-> CrowdStrike Sync script...")
    logger.info("Jira and CrowdStrike Sync Script Started.")
    jira_client = get_jira_client()
    validate_jira_fields(jira_client, CONFIG)
    if not test_jira_connectivity(jira_client):
        print("[ERROR] Jira connectivity test failed. Exiting.")
        sys.exit(1)
    cs_clients = get_cs_clients()
    user_map = validate_user_mappings(jira_client, cs_clients, CONFIG)
    if not user_map:
        logger.warning("No valid user mappings found. Assignee sync may fail.")
    logger.info("Environment checks passed. Starting sync loop.")
    try:
        while True:
            sync_jira_and_crowdstrike(jira_client, cs_clients, user_map)
            logger.info(f"Sleeping for {POLL_INTERVAL} seconds until next poll...")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Script terminated by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error in main loop: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
