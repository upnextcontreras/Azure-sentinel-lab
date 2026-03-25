#!/bin/bash
# =============================================================================
# Script:      1_deploy_infrastructure.sh
# Description: Deploys core Azure infrastructure for Sentinel SIEM lab
#              Creates: Resource Group, Log Analytics Workspace,
#              Microsoft Sentinel, Windows Server 2022 VM
# Author:      Christopher Contreras
# Version:     2.0.0
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

readonly SUBSCRIPTION_ID="your-subscription-id"
readonly RESOURCE_GROUP="rg-sentinel-lab"
readonly LOCATION="eastus"
readonly WORKSPACE_NAME="law-sentinel-lab"
readonly VM_NAME="vm-sentinel"
readonly VM_SIZE="Standard_DC1s_v3"
readonly VM_IMAGE="Win2022Datacenter"
readonly ADMIN_USERNAME="azureuser"
readonly ADMIN_PASSWORD="SentinelLab@2025!"  # Rotate before any production use
readonly AUTO_SHUTDOWN_TIME="2300"
readonly LOG_FILE="./deploy_infrastructure.log"

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
    || fail "Azure CLI not installed. Visit: https://aka.ms/installazurecli"

  az account show &>/dev/null \
    || fail "Not logged in to Azure. Run: az login"

  [[ "$SUBSCRIPTION_ID" != "your-subscription-id" ]] \
    || fail "SUBSCRIPTION_ID not set. Update the CONFIGURATION section."

  log "Prerequisites validated."
}

validate_subscription() {
  log "Setting subscription: $SUBSCRIPTION_ID"

  az account set --subscription "$SUBSCRIPTION_ID" \
    || fail "Failed to set subscription. Verify SUBSCRIPTION_ID is correct."

  log "Subscription set successfully."
}

# =============================================================================
# DEPLOYMENT FUNCTIONS
# =============================================================================

deploy_resource_group() {
  log "Deploying resource group: $RESOURCE_GROUP"

  if az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    warn "Resource group '$RESOURCE_GROUP' already exists. Skipping creation."
    return 0
  fi

  az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --tags \
      Environment=Lab \
      Project=SentinelPortfolio \
      Owner=ChristopherContreras \
    --output none \
    || fail "Failed to create resource group."

  log "Resource group created: $RESOURCE_GROUP"
}

deploy_log_analytics_workspace() {
  log "Deploying Log Analytics workspace: $WORKSPACE_NAME"

  if az monitor log-analytics workspace show \
      --resource-group "$RESOURCE_GROUP" \
      --workspace-name "$WORKSPACE_NAME" &>/dev/null; then
    warn "Workspace '$WORKSPACE_NAME' already exists. Skipping creation."
    return 0
  fi

  az monitor log-analytics workspace create \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --location "$LOCATION" \
    --sku PerGB2018 \
    --retention-time 30 \
    --tags \
      Environment=Lab \
      Project=SentinelPortfolio \
    --output none \
    || fail "Failed to create Log Analytics workspace."

  log "Log Analytics workspace created: $WORKSPACE_NAME"
}

enable_sentinel() {
  log "Enabling Microsoft Sentinel on workspace: $WORKSPACE_NAME"

  az sentinel onboarding-state create \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --name "default" \
    --output none 2>/dev/null \
    || warn "Sentinel may already be enabled or encountered an issue. Verify in portal."

  log "Microsoft Sentinel enabled."
}

deploy_virtual_machine() {
  log "Deploying VM: $VM_NAME ($VM_IMAGE, $VM_SIZE)"

  if az vm show \
      --resource-group "$RESOURCE_GROUP" \
      --name "$VM_NAME" &>/dev/null; then
    warn "VM '$VM_NAME' already exists. Skipping creation."
    return 0
  fi

  az vm create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --image "$VM_IMAGE" \
    --size "$VM_SIZE" \
    --admin-username "$ADMIN_USERNAME" \
    --admin-password "$ADMIN_PASSWORD" \
    --location "$LOCATION" \
    --public-ip-sku Standard \
    --nsg-rule RDP \
    --tags \
      Environment=Lab \
      Project=SentinelPortfolio \
    --output none \
    || fail "Failed to deploy VM."

  log "VM deployed: $VM_NAME"
}

configure_auto_shutdown() {
  log "Configuring auto-shutdown at ${AUTO_SHUTDOWN_TIME} UTC..."

  az vm auto-shutdown \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --time "$AUTO_SHUTDOWN_TIME" \
    --location "$LOCATION" \
    --output none \
    || warn "Auto-shutdown config failed. Set manually in portal to avoid credit drain."

  log "Auto-shutdown configured."
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
  local workspace_id vm_ip

  workspace_id=$(az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query customerId -o tsv)

  vm_ip=$(az vm show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --show-details \
    --query publicIps -o tsv)

  echo ""
  echo "=============================================="
  echo " DEPLOYMENT COMPLETE"
  echo "=============================================="
  echo " Resource Group : $RESOURCE_GROUP"
  echo " Location       : $LOCATION"
  echo " Workspace      : $WORKSPACE_NAME"
  echo " Workspace ID   : $workspace_id"
  echo " VM Name        : $VM_NAME"
  echo " VM Public IP   : $vm_ip"
  echo " Log File       : $LOG_FILE"
  echo "=============================================="
  echo " NEXT STEP: Run 2_connect_data_sources.sh"
  echo "=============================================="
  echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
  log "========================================"
  log " Starting Sentinel Lab Deployment"
  log "========================================"

  validate_prerequisites
  validate_subscription
  deploy_resource_group
  deploy_log_analytics_workspace
  enable_sentinel
  deploy_virtual_machine
  configure_auto_shutdown
  print_summary

  log "Deployment completed successfully."
}

main "$@"
