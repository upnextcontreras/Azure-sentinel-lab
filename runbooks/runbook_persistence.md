# Incident Response Runbook — Persistence via New Local Account
**MITRE ATT&CK:** T1136.001 — Create Account: Local Account  
**Sentinel Rule:** Persistence - New Local User Account Created  
**Severity:** Medium  
**NIST IR Phase Reference:** SP 800-61r2

---

## Overview
Adversaries may create local accounts to maintain persistent access to a compromised system. Unlike domain accounts, local accounts can survive domain policy changes and are often used as backdoors. This runbook covers the detection and response to unauthorized local account creation.

---

## Phase 1 — Preparation
**Prerequisites before this runbook is needed:**
- Sentinel analytics rule active and ingesting SecurityEvent logs
- Responder has local admin or RDP access to affected host
- Known good baseline of local accounts documented for each host
- Change management process understood

---

## Phase 2 — Detection & Analysis

### 2.1 Triage the Incident
1. Open the incident in **Microsoft Sentinel → Incidents**
2. Note:
   - New account name (`NewAccount`)
   - Who created it (`CreatedBy`)
   - Timestamp
   - Host where account was created

### 2.2 Confirm the Account Creation
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4720
| extend
    NewAccount = TargetUserName,
    CreatedBy  = SubjectUserName
| project TimeGenerated, Computer, NewAccount, CreatedBy, EventID
| order by TimeGenerated desc
```

### 2.3 Determine if Change was Authorized
- Was this account created by an authorized admin?
- Is there a change ticket or approval for this account?
- Does the account name follow naming conventions?

**If authorized:** Close as benign positive, document approval.  
**If unauthorized:** Proceed with containment immediately.

### 2.4 Check if Account was Added to Privileged Groups
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4728, 4732, 4756)
| extend AddedAccount = MemberName
| where AddedAccount contains "<NEW_ACCOUNT>"
| project TimeGenerated, Computer, AddedAccount, TargetUserName
```

**If the account was also added to a privileged group:** Activate the Privilege Escalation runbook in parallel.

### 2.5 Check for Logon Activity from New Account
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where Account contains "<NEW_ACCOUNT>"
| project TimeGenerated, Account, IpAddress, LogonType, Computer
```

If the account has already been used to log in, treat this as an active compromise.

---

## Phase 3 — Containment

### 3.1 Disable the Unauthorized Account Immediately
RDP into the affected host and run in PowerShell:
```powershell
# Disable the account
net user <NEW_ACCOUNT> /active:no

# Verify
net user <NEW_ACCOUNT>
```

### 3.2 If Account was Used to Log In — Terminate Active Sessions
```powershell
# List active sessions
query session

# Terminate suspicious session (replace ID with session ID)
logoff <SESSION_ID>
```

### 3.3 Remove from Any Privileged Groups
```powershell
net localgroup Administrators <NEW_ACCOUNT> /delete
```

---

## Phase 4 — Eradication

### 4.1 Delete the Unauthorized Account
```powershell
net user <NEW_ACCOUNT> /delete
```

### 4.2 Audit All Account Creations in Past 7 Days
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4720
| extend NewAccount = TargetUserName, CreatedBy = SubjectUserName
| project TimeGenerated, Computer, NewAccount, CreatedBy
| order by TimeGenerated desc
```

### 4.3 Check for Additional Persistence Mechanisms
Adversaries often establish multiple persistence methods simultaneously:

```powershell
# Check for suspicious scheduled tasks
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike "\Microsoft*" -and
    $_.State -eq "Ready"
} | Select TaskName, TaskPath, State

# Check for new services
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | 
    Select Name, DisplayName, Status

# Check registry run keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

### 4.4 Investigate the Creator Account
If `CreatedBy` is an unexpected account, investigate it:
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where SubjectUserName == "<CREATED_BY_ACCOUNT>"
| summarize count() by EventID, Activity
| order by count_ desc
```

---

## Phase 5 — Recovery
- Confirm unauthorized account has been deleted
- Verify no remaining persistence mechanisms exist
- Confirm privileged group membership matches approved baseline
- If creator account was compromised: reset password, revoke sessions, force MFA re-registration

---

## Phase 6 — Post-Incident Activity
- [ ] Update Sentinel incident status to **Closed** with classification
- [ ] Document full timeline in incident comments
- [ ] Update local account baseline documentation
- [ ] Review whether account creation should require approval workflow
- [ ] Consider implementing Windows LAPS for local admin account management
- [ ] Document lessons learned

---

*Runbook Author: Christopher Contreras*  
*Aligned to: NIST SP 800-61r2 | MITRE ATT&CK T1136.001*
