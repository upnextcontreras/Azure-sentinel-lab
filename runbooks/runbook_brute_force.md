# Incident Response Runbook — Brute Force Attack
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing  
**Sentinel Rule:** Brute Force - Repeated Authentication Failures  
**Severity:** Medium (escalate to High if successful authentication follows)  
**NIST IR Phase Reference:** SP 800-61r2

---

## Overview
A brute force attack involves an adversary systematically attempting multiple passwords against one or more accounts to gain unauthorized access. This runbook covers detection, analysis, containment, eradication, and recovery for brute force activity detected against Azure-hosted Windows infrastructure.

---

## Phase 1 — Preparation
**Prerequisites before this runbook is needed:**
- Sentinel analytics rule active and ingesting SecurityEvent logs
- On-call responder has access to Azure portal and Log Analytics
- NSG modify permissions confirmed for responder account
- Escalation contact list available

---

## Phase 2 — Detection & Analysis

### 2.1 Triage the Incident
1. Open the incident in **Microsoft Sentinel → Incidents**
2. Note the following from the incident details:
   - Source IP address
   - Target accounts
   - Attack start and end time
   - Number of failed attempts

### 2.2 Confirm the Attack Pattern
Run the following KQL query in Log Analytics to confirm the brute force pattern:

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| where IpAddress == "<SOURCE_IP>"
| summarize
    FailureCount = count(),
    TargetAccounts = make_set(Account),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
```

### 2.3 Check for Successful Authentication
**Critical step** — determine if the attacker succeeded:

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where IpAddress == "<SOURCE_IP>"
| project TimeGenerated, Account, IpAddress, LogonType, Computer
```

**If results return:** Escalate severity to HIGH and activate lateral movement procedures immediately.  
**If no results:** Proceed with standard containment below.

### 2.4 Determine Scope
- Is this a single IP or distributed (multiple IPs, same pattern)?
- Are targeted accounts privileged (admins, service accounts)?
- Is the source IP internal or external?

---

## Phase 3 — Containment

### 3.1 Block Source IP at NSG
```
Portal → Virtual Machines → vm-sentinel → 
Networking → Add inbound security rule

Source: IP address → <ATTACKER_IP>
Destination: Any
Action: Deny
Priority: 100
Name: block-brute-force-<DATE>
```

### 3.2 Verify Block is Active
```kql
SecurityEvent
| where TimeGenerated > ago(10m)
| where EventID == 4625
| where IpAddress == "<SOURCE_IP>"
```
Should return no new results after the NSG rule is applied.

---

## Phase 4 — Eradication

### 4.1 Check for Unauthorized Changes During Attack Window
Verify no new accounts were created:
```kql
SecurityEvent
| where TimeGenerated between (<ATTACK_START> .. <ATTACK_END>)
| where EventID == 4720
| project TimeGenerated, TargetUserName, SubjectUserName, Computer
```

Verify no privilege escalation occurred:
```kql
SecurityEvent
| where TimeGenerated between (<ATTACK_START> .. <ATTACK_END>)
| where EventID in (4728, 4732, 4756)
| project TimeGenerated, TargetUserName, SubjectUserName, TargetGroup
```

### 4.2 Harden Authentication
If the attack targeted RDP, restrict RDP access:
```
Portal → VM → Networking → NSG → 
Restrict RDP (3389) to your management IP only
```

---

## Phase 5 — Recovery
- Remove temporary NSG block after 24-hour observation period (if no recurrence)
- Confirm no unauthorized access occurred during attack window
- Re-enable any temporarily disabled accounts if applicable
- Document timeline and actions taken in the Sentinel incident comments

---

## Phase 6 — Post-Incident Activity
- [ ] Update Sentinel incident status to **Closed** with classification
- [ ] Add attacker IP to threat intelligence watchlist
- [ ] Review detection rule threshold — tune if false positives occurred
- [ ] Document lessons learned
- [ ] Consider enabling MFA if not already enforced

---

*Runbook Author: Christopher Contreras*  
*Aligned to: NIST SP 800-61r2 | MITRE ATT&CK T1110.001*
