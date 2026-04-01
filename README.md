# Azure Sentinel Threat Detection & Incident Response Lab

A cloud-native SIEM lab built from scratch on Microsoft Azure using CLI scripts. This project covers threat detection engineering, custom KQL analytics rules mapped to MITRE ATT&CK, live attack simulation, and NIST SP 800-61 aligned incident response runbooks.

## Demo
[Watch the full project walkthrough](https://www.loom.com/share/255976d5087240e798541715663b3a5b)

---

## Project Overview

This lab demonstrates end-to-end security operations on Azure, from infrastructure deployment to incident response. Everything is built and configured using Azure CLI scripts to reflect real-world infrastructure-as-code practices used in enterprise environments.

**Security Engineering focus:** Custom detection rules, MITRE ATT&CK mapping, attack simulation, incident response  
**Cloud Engineering focus:** Log pipeline design, data ingestion architecture, infrastructure automation, Azure Monitor

---

## Architecture

```
Windows Server 2022 VM
        |
        | (Windows Security Events via AMA)
        v
Log Analytics Workspace (law-sentinel-lab)
        ^                        ^
        |                        |
Azure Activity Logs        Entra ID Sign-in
                                 & Audit Logs
        |
        v
Microsoft Sentinel
        |
        v
Custom KQL Analytics Rules
        |
        v
Incidents + Alerts
```

---

## Repository Structure

```
azure-sentinel-lab/
├── README.md
├── scripts/
│   ├── 1_deploy_infrastructure.sh   # Deploys RG, workspace, Sentinel, VM
│   ├── 2_connect_data_sources.sh    # Connects data sources via CLI + MMA agent
│   └── 3_deploy_kql_rules.sh        # Deploys 4 KQL analytics rules to Sentinel
└── runbooks/
    ├── runbook_brute_force.md        # NIST IR runbook for T1110.001
    ├── runbook_privilege_escalation.md  # NIST IR runbook for T1078.003
    └── runbook_persistence.md        # NIST IR runbook for T1136.001
```

---

## Prerequisites

- Azure subscription (free trial works)
- Azure CLI installed and authenticated (`az login`)
- Bash terminal (Git Bash on Windows, Terminal on Mac/Linux)

---

## Deployment

### Step 1 — Deploy Infrastructure

Update `SUBSCRIPTION_ID` in `1_deploy_infrastructure.sh` with your subscription ID, then run:

```bash
bash scripts/1_deploy_infrastructure.sh
```

This deploys:
- Resource group `rg-sentinel-lab`
- Log Analytics workspace `law-sentinel-lab`
- Microsoft Sentinel enabled on the workspace
- Windows Server 2022 VM `vm-sentinel` (Standard_D2s_v3, East US)
- Auto-shutdown configured at 11 PM UTC

### Step 2 — Connect Data Sources

```bash
bash scripts/2_connect_data_sources.sh
```

This connects:
- MMA agent installed on VM and connected to workspace
- Azure Activity logs via diagnostic settings

**Two manual portal steps required** (Microsoft CLI limitation):

**Windows Security Events:**
```
Sentinel → Content Hub → Search "Windows Security Events" → Install
→ Data connectors → Windows Security Events via AMA → Open connector
→ Create data collection rule → Add vm-sentinel → All Security Events → Create
```

**Microsoft Entra ID:**
```
Sentinel → Content Hub → Search "Microsoft Entra ID" → Install
→ Data connectors → Microsoft Entra ID → Open connector
→ Enable Sign-in logs + Audit logs → Apply Changes
```

### Step 3 — Deploy KQL Detection Rules

```bash
bash scripts/3_deploy_kql_rules.sh
```

Deploys 4 custom analytics rules to Sentinel. Verify in:
```
Sentinel → Analytics → Active rules
```

---

## Detection Rules

| Rule | MITRE Technique | Severity | Trigger |
|------|----------------|----------|---------|
| Brute Force - Repeated Authentication Failures | T1110.001 | Medium | 10+ failed logons from single IP in 5 min |
| Privilege Escalation - User Added to Privileged Group | T1078.003 | High | Account added to Administrators/Domain Admins |
| Persistence - New Local User Account Created | T1136.001 | Medium | New local user account created |
| Password Spraying - Single IP Targeting Multiple Accounts | T1110.003 | High | Single IP failing against 5+ accounts in 30 min |

---

## Attack Simulation

RDP into `vm-sentinel` and run the following in PowerShell to trigger all detection rules:

```powershell
# Brute Force (triggers T1110.001)
$i = 0
while ($i -lt 15) {
    Start-Process -FilePath "net" -ArgumentList "use \\localhost\IPC$ /user:fakeuser wrongpassword" -Wait 2>$null
    $i++
}

# Persistence (triggers T1136.001)
net user backdooruser Password123! /add

# Privilege Escalation (triggers T1078.003)
net localgroup Administrators backdooruser /add
```

Wait 5-10 minutes, then check:
```
Sentinel → Incidents
```

---

## Incident Response Runbooks

Three NIST SP 800-61 aligned runbooks are included in the `runbooks/` directory:

| Runbook | Attack Scenario | MITRE Technique |
|---------|----------------|-----------------|
| runbook_brute_force.md | Repeated authentication failures | T1110.001 |
| runbook_privilege_escalation.md | Unauthorized privilege escalation | T1078.003 |
| runbook_persistence.md | New local account creation | T1136.001 |

Each runbook covers: Preparation, Detection & Analysis, Containment, Eradication, Recovery, and Post-Incident Activity.

---

## Cost Management

This lab is designed to run on an Azure free trial ($200 credit). Key cost controls:
- VM auto-shutdown configured at 11 PM UTC
- Log Analytics on Pay-as-you-go tier
- Sentinel is free for the first 31 days on a new workspace
- Stop/deallocate VM when not in use to avoid charges

---

## Skills Demonstrated

**Security Engineering**
- SIEM deployment and configuration
- Custom detection rule authoring (KQL)
- MITRE ATT&CK framework mapping
- Attack simulation and detection validation
- NIST SP 800-61 incident response

**Cloud Engineering**
- Azure CLI infrastructure automation
- Log pipeline design and architecture
- Data Collection Rules (DCR) configuration
- Azure Monitor Agent deployment
- Infrastructure tagging and governance

---

*Built by Christopher Contreras*  
*linkedin.com/in/christopher-d-contreras*
