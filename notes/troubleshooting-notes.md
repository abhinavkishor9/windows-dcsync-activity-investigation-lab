# Troubleshooting Notes — DCSync Activity Investigation

## 1. NTDS Service Was Not Found

### Symptom

```powershell
Get-Service NTDS -ErrorAction SilentlyContinue
```

returned no result.

### Cause

The endpoint is a standalone Windows workstation:

```text
Domain     : WORKGROUP
DomainRole : 0
```

The NTDS service is associated with Active Directory Domain Services and is therefore not expected on this workstation.

### Correct Response

Do not attempt to create the NTDS service.

Document the result as an environment limitation.

---

## 2. NTDS.dit Was Not Found

### Symptom

```powershell
Test-Path "C:\Windows\NTDS\ntds.dit"
```

returned:

```text
False
```

### Cause

The machine is not a Domain Controller.

### Correct Response

Do not download or manually create an `NTDS.dit` file.

The absence of the database is expected on this endpoint.

---

## 3. Security Event 4662 Was Not Available

### Symptom

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Possible Reasons

- The endpoint is not a Domain Controller.
- The relevant auditing configuration is not enabled.
- The queried event does not exist in the current Security log.
- The required Active Directory environment is unavailable.

### Correct Response

Do not fabricate Event ID 4662.

Record the absence as a telemetry limitation.

---

## 4. Security Events 4624 and 4672 Were Not Available

### Symptom

Both queries returned:

```text
No events were found that match the specified selection criteria.
```

### Correct Response

Do not assume that authentication did not occur.

The correct conclusion is:

> Authentication context could not be established from the queried Security events.

---

## 5. Sysmon Returned Many Process Events

### Symptom

The keyword-filtered Event ID 1 query returned many events.

### Problem

The output was summarized as:

```text
Process Create:...
```

This does not reveal enough information to establish which process generated the event or what it actually executed.

### Correct Response

Do not classify every PowerShell, CMD, LSASS, or NTDS keyword match as DCSync.

For a stronger investigation, obtain fields such as:

- Image
- CommandLine
- ParentImage
- ParentCommandLine
- User
- ProcessId
- ParentProcessId
- Hashes

---

## 6. Sysmon Network Events Were Not Enough

### Symptom

Event ID 3 returned many network connections.

### Problem

The displayed output only showed:

```text
Network connection detected:...
```

### Correct Response

Do not interpret generic network activity as Domain Controller replication.

A useful network investigation should establish:

```text
Source Process
      |
Source Host
      |
Source IP
      |
Destination IP
      |
Destination Port
      |
Timestamp
```

Without this correlation, the network events remain supporting telemetry only.

---

## 7. Wazuh Showed PowerShell Activity

### Observation

A Wazuh event showed:

```text
Image:
C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

Process ID:
20288
```

### Important

PowerShell activity does not automatically indicate DCSync.

The event must be correlated with:

- Command line
- Account
- Parent process
- Destination
- Security events
- Replication-related object access

---

## 8. Wazuh Search Returned No DCSync Alert

### Possible Cause

DCSync-specific activity may not be present, or the required telemetry may not be collected.

### Correct Approach

Check both:

```text
wazuh-alerts-*
```

and:

```text
wazuh-archives-*
```

Then search for:

```text
4662
```

```text
DS-Replication
```

```text
DCSync
```

```text
Replicating Directory Changes
```

---

## 9. `$LabPath` Is Missing

### Symptom

Evidence commands fail because `$LabPath` is empty or undefined.

### Fix

Reinitialize:

```powershell
$LabPath = "C:\DCSyncLab"

New-Item -ItemType Directory -Path $LabPath -Force
New-Item -ItemType Directory -Path "$LabPath\Evidence" -Force
```

Verify:

```powershell
Test-Path "$LabPath\Evidence"
```

Expected:

```text
True
```

---

## 10. Do Not Manufacture Active Directory Evidence

This is the most important troubleshooting principle for this lab.

Do not:

- Create a fake `NTDS.dit`.
- Create a fake NTDS service.
- Inject fabricated Event ID 4662 records.
- Treat generic Sysmon events as DCSync.
- Treat PowerShell activity as proof of credential access.
- Treat the absence of 4662 as proof that no DCSync occurred.

Instead:

```text
Missing Evidence
      ↓
Document the Gap
      ↓
Identify What Would Be Required
      ↓
State the Investigation Limitation
```

---

## 11. Correct Pivot for Future DCSync Testing

A genuine DCSync investigation requires an isolated Active Directory lab containing:

```text
Windows Server Domain Controller
        |
        +-- Active Directory Domain Services
        |
        +-- Directory replication
        |
        +-- Security auditing
        |
        +-- Sysmon
        |
        +-- Wazuh Agent
```

The current Windows 11 WORKGROUP machine should be used for **detection logic and telemetry analysis**, not genuine DCSync execution.

## Final Troubleshooting Principle

When the environment cannot produce the artifact being investigated, the correct DFIR response is not to manufacture the artifact.

> **Validate the environment → validate the telemetry → investigate what exists → document what is missing.**
