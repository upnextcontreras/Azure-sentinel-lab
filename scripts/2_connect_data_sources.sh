#!/bin/bash
# =============================================================================
# Script:      2_connect_data_sources.sh
# Description: Connects data sources to Microsoft Sentinel
#              Sources: Windows Security Events (via MMA),
#              Azure Activity Logs
#              Note: Entra ID + Windows Security Events via AMA connectors
#              require manual portal steps (documented below)
# Author:      Christopher Contreras
# Version:     2.0.0
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

readonly RESOURCE_GROUP="rg-sentinel-lab"
readonly WORKSPACE_NAME="law-sentinel-lab"
readonly VM_NAME="vm-sentinel"
readonly LOCATION="eastus"
readonly DIAG_SETTING_NAME="sentinel-activity-logs"
readonly LOG_FILE="./connect_data_sources.log"

# =============================================================================
# LOGGING
# =============================================================================

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*" | tee -a "$LOG_FILE"; }
warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*" | tee -a "$LOG_FILE"; }
fail() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE"; exit 1; }

# =============================================================================
# VALIDATION
# =============================================================================

validate_prerequisites() {
  log "Validating prerequisites..."

  command -v az &>/dev/null \
    || fail "Azure CLI not installed."

  az account show &>/dev/null \
    || fail "Not logged in to Azure. Run: az login"

  az group show --name "$RESOURCE_GROUP" &>/dev/null \
    || fail "Resource group '$RESOURCE_GROUP' not found. Run 1_deploy_infrastructure.sh first."

  az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" &>/dev/null \
    || fail "Workspace '$WORKSPACE_NAME' not found. Run 1_deploy_infrastructure.sh first."

  az vm show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" &>/dev/null \
    || fail "VM '$VM_NAME' not found. Run 1_deploy_infrastructure.sh first."

  log "Prerequisites validated."
}

# =============================================================================
# DATA SOURCE FUNCTIONS
# =============================================================================

install_mma_agent() {
  log "Installing Log Analytics (MMA) agent on VM: $VM_NAME"

  local extension_state
  extension_state=$(az vm extension show \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name "MicrosoftMonitoringAgent" \
    --query provisioningState -o tsv 2>/dev/null || echo "NotInstalled")

  if [[ "$extension_state" == "Succeeded" ]]; then
    warn "MMA agent already installed. Skipping."
    return 0
  fi

  local workspace_id workspace_key
  workspace_id=$(az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query customerId -o tsv)

  workspace_key=$(az monitor log-analytics workspace get-shared-keys \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query primarySharedKey -o tsv)

  az vm extension set \
    --resource-group "$RESOURCE_GROUP" \
    --vm-name "$VM_NAME" \
    --name MicrosoftMonitoringAgent \
    --publisher Microsoft.EnterpriseCloud.Monitoring \
    --version 1.0 \
    --settings "{\"workspaceId\": \"$workspace_id\"}" \
    --protected-settings "{\"workspaceKey\": \"$workspace_key\"}" \
    --output none \
    || fail "Failed to install MMA agent."

  log "MMA agent installed and connected to workspace."
}

connect_azure_activity_logs() {
  log "Connecting Azure Activity logs to workspace..."

  local subscription_id workspace_id

  subscription_id=$(az account show --query id -o tsv)
  workspace_id=$(az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query id -o tsv)

  az monitor diagnostic-settings create \
    --name "$DIAG_SETTING_NAME" \
    --resource "/subscriptions/$subscription_id" \
    --workspace "$workspace_id" \
    --logs '[
      {"category": "Administrative", "enabled": true},
      {"category": "Security",       "enabled": true},
      {"category": "Policy",         "enabled": true}
    ]' \
    --output none 2>/dev/null \
    || warn "Diagnostic setting may already exist. Verify in portal."

  log "Azure Activity logs connected."
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
  echo ""
  echo "=============================================="
  echo " DATA SOURCES CONNECTED"
  echo "=============================================="
  echo " [✓] MMA Agent installed on VM"
  echo " [✓] Azure Activity logs connected"
  echo ""
  echo " [!] MANUAL STEPS REQUIRED IN PORTAL:"
  echo ""
  echo " 1. Windows Security Events via AMA:"
  echo "    Sentinel → Content Hub → Search"
  echo "    'Windows Security Events' → Install"
  echo "    → Data connectors → Windows Security"
  echo "    Events via AMA → Open connector"
  echo "    → Create data collection rule"
  echo "    → Add vm-sentinel → All Security Events"
  echo ""
  echo " 2. Microsoft Entra ID:"
  echo "    Sentinel → Content Hub → Search"
  echo "    'Microsoft Entra ID' → Install"
  echo "    → Data connectors → Microsoft Entra ID"
  echo "    → Open connector → Connect"
  echo "    → Enable Sign-in logs + Audit logs"
  echo "=============================================="
  echo " NEXT STEP: Complete manual steps above"
  echo "            then run 3_deploy_kql_rules.sh"
  echo "=============================================="
  echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
  log "========================================"
  log " Connecting Sentinel Data Sources"
  log "========================================"

  validate_prerequisites
  install_mma_agent
  connect_azure_activity_logs
  print_summary

  log "Data source connection completed."
}

main "$@"
