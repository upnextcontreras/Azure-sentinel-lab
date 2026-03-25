# Incident Response Runbook — Privilege Escalation
**MITRE ATT&CK:** T1078.003 — Valid Accounts: Local Accounts  
**Sentinel Rule:** Privilege Escalation - User Added to Privileged Group  
**Severity:** High  
**NIST IR Phase Reference:** SP 800-61r2

---

## Overview
Privilege escalation occurs when an adversary gains elevated permissions beyond what was initially granted. This runbook covers the detection and response to unauthorized addition of accounts to privileged groups such as Administrators, Domain Admins, or Enterprise Admins.

---

## Phase 1 — Preparation
**Prerequisites before this runbook is needed:**
- Sentinel analytics rule active and ingesting SecurityEvent logs
- Responder has User Administrator or equivalent permissions
- Change management process understood — distinguish authorized vs unauthorized changes
- Known good baseline of privileged group membership documented

---

## Phase 2 — Detection & Analysis

### 2.1 Triage the Incident
1. Open the incident in **Microsoft Sentinel → Incidents**
2. Note:
   - Which account was added (`AddedAccount`)
   - Which group was modified (`TargetGroup`)
   - Who performed the action (`Actor`)
   - Timestamp of the change
   - Host where the change occurred

### 2.2 Confirm the Event
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4728, 4732, 4756)
| extend
    AddedAccount = MemberName,
    TargetGroup  = TargetUserName,
    Actor        = SubjectUserName
| project TimeGenerated, Computer, Actor, AddedAccount, TargetGroup, EventID
| order by TimeGenerated desc
```

### 2.3 Determine if Change was Authorized
- Was this a scheduled maintenance window?
- Is the Actor account a known admin?
- Was a change ticket submitted?

**If authorized:** Close incident as benign positive, document approval reference.  
**If unauthorized:** Proceed with containment immediately.

### 2.4 Investigate the Actor Account
Check what else the actor account did around the same time:
```kql
SecurityEvent
| where TimeGenerated > ago(2h)
| where SubjectUserName == "<ACTOR_ACCOUNT>"
| project TimeGenerated, EventID, Activity, Computer, TargetUserName
| order by TimeGenerated asc
```

---

## Phase 3 — Containment

### 3.1 Remove Unauthorized Account from Privileged Group
RDP into the affected host and run in PowerShell:
```powershell
# Remove from local Administrators
net localgroup Administrators <ADDED_ACCOUNT> /delete

# Verify removal
net localgroup Administrators
```

### 3.2 Disable the Unauthorized Account
```powershell
net user <ADDED_ACCOUNT> /active:no
```

### 3.3 Disable the Actor Account (if compromised)
If the actor account appears to be compromised:
```
Portal → Entra ID → Users → <ACTOR_ACCOUNT> → 
Edit → Account enabled → No → Save
```

Also revoke active sessions:
```
Entra ID → Users → <ACTOR_ACCOUNT> → Revoke sessions
```

---

## Phase 4 — Eradication

### 4.1 Audit All Privileged Group Changes in the Past 7 Days
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)
| extend
    AddedAccount = MemberName,
    TargetGroup  = TargetUserName,
    Actor        = SubjectUserName
| project TimeGenerated, Computer, Actor, AddedAccount, TargetGroup
| order by TimeGenerated desc
```

### 4.2 Review All Actions Taken by Unauthorized Account
Check for any damage done while the account had elevated privileges:
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where SubjectUserName == "<ADDED_ACCOUNT>"
| summarize count() by EventID, Activity
| order by count_ desc
```

### 4.3 Check for Persistence Mechanisms
Verify no scheduled tasks, services, or registry run keys were added:
```powershell
# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}

# Check startup items
Get-CimInstance Win32_StartupCommand
```

---

## Phase 5 — Recovery
- Confirm privileged group membership matches approved baseline
- Re-enable actor account only after confirming it was not compromised
- Force password reset on any affected accounts
- Review and update privileged access baseline documentation

---

## Phase 6 — Post-Incident Activity
- [ ] Update Sentinel incident status to **Closed** with classification
- [ ] Document unauthorized account and actor in incident timeline
- [ ] Review whether Just-In-Time (JIT) access should be enforced
- [ ] Consider implementing Privileged Identity Management (PIM) in Entra ID
- [ ] Document lessons learned

---

*Runbook Author: Christopher Contreras*  
*Aligned to: NIST SP 800-61r2 | MITRE ATT&CK T1078.003*
