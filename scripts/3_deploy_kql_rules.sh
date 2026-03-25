#!/bin/bash
# =============================================================================
# Script:      3_deploy_kql_rules.sh
# Description: Deploys 4 custom KQL analytics rules to Microsoft Sentinel
#              Rules mapped to MITRE ATT&CK framework:
#              - T1110.001 Brute Force
#              - T1078.003 Privilege Escalation
#              - T1136.001 Persistence
#              - T1110.003 Password Spraying
# Author:      Christopher Contreras
# Version:     2.0.0
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

readonly RESOURCE_GROUP="rg-sentinel-lab"
readonly WORKSPACE_NAME="law-sentinel-lab"
readonly LOG_FILE="./deploy_kql_rules.log"

# =============================================================================
# LOGGING
# =============================================================================

log()     { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*" | tee -a "$LOG_FILE"; }
warn()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*" | tee -a "$LOG_FILE"; }
fail()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE"; exit 1; }
success() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]    $*" | tee -a "$LOG_FILE"; }

# =============================================================================
# VALIDATION
# =============================================================================

validate_prerequisites() {
  log "Validating prerequisites..."

  command -v az &>/dev/null \
    || fail "Azure CLI not installed."

  az account show &>/dev/null \
    || fail "Not logged in to Azure. Run: az login"

  az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" &>/dev/null \
    || fail "Workspace not found. Run previous scripts first."

  log "Prerequisites validated."
}

# =============================================================================
# RULE DEPLOYMENT HELPER
# =============================================================================

deploy_rule() {
  local name="$1"
  local display_name="$2"
  local scheduled_json="$3"

  log "Deploying rule: $display_name"

  az sentinel alert-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --name "$name" \
    --scheduled "$scheduled_json" \
    --output none \
    || fail "Failed to deploy rule: $display_name"

  success "Rule deployed: $display_name"
}

# =============================================================================
# ANALYTICS RULES
# =============================================================================

deploy_brute_force_rule() {
  deploy_rule \
    "brute-force-detection" \
    "Brute Force - Repeated Authentication Failures" \
    '{
      "displayName": "Brute Force - Repeated Authentication Failures",
      "description": "Detects 10+ failed logon attempts from a single IP within 5 minutes. MITRE T1110.001.",
      "severity": "Medium",
      "enabled": true,
      "query": "SecurityEvent | where TimeGenerated > ago(5m) | where EventID == 4625 | summarize FailureCount = count(), TargetAccounts = make_set(Account, 20), FirstAttempt = min(TimeGenerated), LastAttempt = max(TimeGenerated) by IpAddress, Computer, bin(TimeGenerated, 5m) | where FailureCount >= 10 | extend MITRETechnique = \"T1110.001\"",
      "queryFrequency": "PT5M",
      "queryPeriod": "PT5M",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0,
      "suppressionEnabled": false,
      "suppressionDuration": "PT1H",
      "tactics": ["CredentialAccess"],
      "techniques": ["T1110"]
    }'
}

deploy_privilege_escalation_rule() {
  deploy_rule \
    "privilege-escalation-detection" \
    "Privilege Escalation - User Added to Privileged Group" \
    '{
      "displayName": "Privilege Escalation - User Added to Privileged Group",
      "description": "Detects accounts added to Administrators, Domain Admins, or Enterprise Admins. MITRE T1078.003.",
      "severity": "High",
      "enabled": true,
      "query": "SecurityEvent | where TimeGenerated > ago(15m) | where EventID in (4728, 4732, 4756) | extend AddedAccount = MemberName, TargetGroup = TargetUserName, Actor = SubjectUserName | where TargetGroup has_any (\"Administrators\", \"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\") | project TimeGenerated, Computer, Actor, AddedAccount, TargetGroup, EventID | extend MITRETechnique = \"T1078.003\"",
      "queryFrequency": "PT15M",
      "queryPeriod": "PT15M",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0,
      "suppressionEnabled": false,
      "suppressionDuration": "PT1H",
      "tactics": ["PrivilegeEscalation"],
      "techniques": ["T1078"]
    }'
}

deploy_persistence_rule() {
  deploy_rule \
    "persistence-new-account" \
    "Persistence - New Local User Account Created" \
    '{
      "displayName": "Persistence - New Local User Account Created",
      "description": "Detects creation of new local user accounts, a common persistence technique. MITRE T1136.001.",
      "severity": "Medium",
      "enabled": true,
      "query": "SecurityEvent | where TimeGenerated > ago(1h) | where EventID == 4720 | extend NewAccount = TargetUserName, CreatedBy = SubjectUserName, AccountSID = TargetSid | project TimeGenerated, Computer, NewAccount, CreatedBy, AccountSID, EventID | extend MITRETechnique = \"T1136.001\"",
      "queryFrequency": "PT1H",
      "queryPeriod": "PT1H",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0,
      "suppressionEnabled": false,
      "suppressionDuration": "PT4H",
      "tactics": ["Persistence"],
      "techniques": ["T1136"]
    }'
}

deploy_password_spray_rule() {
  deploy_rule \
    "password-spray-detection" \
    "Password Spraying - Single IP Targeting Multiple Accounts" \
    '{
      "displayName": "Password Spraying - Single IP Targeting Multiple Accounts",
      "description": "Detects a single IP failing against 5+ distinct accounts in 30 minutes. MITRE T1110.003.",
      "severity": "High",
      "enabled": true,
      "query": "SecurityEvent | where TimeGenerated > ago(30m) | where EventID == 4625 | summarize FailureCount = count(), DistinctAccounts = dcount(Account), AccountList = make_set(Account, 20), FirstAttempt = min(TimeGenerated), LastAttempt = max(TimeGenerated) by IpAddress, bin(TimeGenerated, 30m) | where DistinctAccounts >= 5 | extend MITRETechnique = \"T1110.003\"",
      "queryFrequency": "PT30M",
      "queryPeriod": "PT30M",
      "triggerOperator": "GreaterThan",
      "triggerThreshold": 0,
      "suppressionEnabled": false,
      "suppressionDuration": "PT1H",
      "tactics": ["CredentialAccess"],
      "techniques": ["T1110"]
    }'
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
  echo ""
  echo "=============================================="
  echo " KQL ANALYTICS RULES DEPLOYED"
  echo "=============================================="
  echo " [✓] Brute Force Detection          T1110.001"
  echo " [✓] Privilege Escalation Detection T1078.003"
  echo " [✓] Persistence Detection          T1136.001"
  echo " [✓] Password Spray Detection       T1110.003"
  echo ""
  echo " Verify in portal:"
  echo " Sentinel → Analytics → Active rules"
  echo "=============================================="
  echo " NEXT STEP: Trigger test attacks then verify"
  echo "            incidents in Sentinel → Incidents"
  echo "=============================================="
  echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
  log "========================================"
  log " Deploying Sentinel KQL Analytics Rules"
  log "========================================"

  validate_prerequisites
  deploy_brute_force_rule
  deploy_privilege_escalation_rule
  deploy_persistence_rule
  deploy_password_spray_rule
  print_summary

  log "All rules deployed successfully."
}

main "$@"
