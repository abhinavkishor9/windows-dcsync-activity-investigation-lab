# Investigation Notes — DCSync Activity Investigation

## Investigation Summary

The investigation examined whether the Windows endpoint contained evidence consistent with DCSync activity.

The first step was to determine whether the endpoint could actually participate in Active Directory replication. The host reported `WORKGROUP` with `DomainRole 0`, identifying it as a standalone workstation.

The investigation therefore treated the DCSync hypothesis cautiously and focused on validating the expected artifacts rather than attempting to manufacture replication activity.

## 1. Host Identification

### Command

```powershell
Get-CimInstance Win32_ComputerSystem |
Select-Object Name, Domain, DomainRole
```

### Result

```text
Name        : DESKTOP-9MMM37V
Domain      : WORKGROUP
DomainRole  : 0
```

### Interpretation

The endpoint is not a Domain Controller.

This is a critical scoping finding because DCSync is an Active Directory replication technique and requires an Active Directory environment.

---

## 2. Operating System

### Command

```powershell
Get-CimInstance Win32_OperatingSystem |
Select-Object Caption, Version
```

### Result

```text
Caption : Microsoft Windows 11 Pro
Version : 10.0.26200
```

### Interpretation

The endpoint is a Windows 11 Pro workstation.

---

## 3. NTDS Service Investigation

### Command

```powershell
Get-Service NTDS -ErrorAction SilentlyContinue
```

### Result

No NTDS service was returned.

A broader search was also performed:

```powershell
Get-Service |
Where-Object {
    $_.Name -match "NTDS|AD"
} |
Select-Object Status, Name, DisplayName
```

The returned services included:

```text
AdobeARMservice
ADPService
AppReadiness
McAfee WebAdvisor
ushupgradesvc
```

No Active Directory Domain Services service was identified.

### Interpretation

The endpoint does not operate the expected NTDS service.

The presence of a service whose name happens to contain `AD` should not automatically be interpreted as Active Directory evidence.

---

## 4. NTDS.dit Investigation

### Command

```powershell
Test-Path "C:\Windows\NTDS\ntds.dit"
```

### Result

```text
False
```

A directory listing was also performed:

```powershell
Get-ChildItem "C:\Windows\NTDS" -Force -ErrorAction SilentlyContinue |
Select-Object Name, Length, LastWriteTime
```

No files were returned.

### Interpretation

No local `NTDS.dit` database was identified.

On this standalone workstation, that result is expected and does not represent suspicious deletion or tampering.

---

## 5. Investigation Timestamp

### Command

```powershell
Get-Date
```

### Result

```text
17 September 2026 07:10:21
```

This timestamp provides the recorded investigation reference point.

---

## 6. Security Event 4662

### Command

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4662
} -MaxEvents 20 |
Select-Object TimeCreated, Id, ProviderName, Message
```

### Result

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

A second query searched for replication-related terms:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4662
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "Replicating Directory Changes|DS-Replication|1131f6aa|89e95b76|1131f6ad"
} |
Select-Object TimeCreated, Id, Message
```

This also returned no events.

### Interpretation

No Event ID 4662 evidence was available.

Therefore, there is no observed directory-object access telemetry supporting a DCSync conclusion.

---

## 7. Authentication Context

### Event ID 4624

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4624
} -MaxEvents 100 |
Select-Object TimeCreated, Message
```

Result:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Event ID 4672

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4672
} -MaxEvents 100 |
Select-Object TimeCreated, Message
```

Result:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

Authentication context could not be correlated because the queried events were unavailable.

This is a telemetry limitation rather than evidence of malicious activity.

---

## 8. Sysmon Process Investigation

### Query

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 1
} -MaxEvents 500 |
Where-Object {
    $_.Message -match "powershell|cmd.exe|mimikatz|lsass|ntds|replication"
} |
Select-Object TimeCreated, Message
```

### Observed Pattern

Multiple events were returned between approximately:

```text
17-09-2026 07:00:50
17-09-2026 07:03:15
```

The displayed output was summarized as:

```text
Process Create:...
```

### Interpretation

Sysmon process telemetry was available.

However, the extracted output did not expose enough information to establish:

- Exact executable
- Complete command line
- Parent process
- User
- Process relationship
- DCSync-specific behavior

Therefore, these events cannot be treated as proof of DCSync.

---

## 9. Sysmon Network Investigation

### Query

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 3
} -MaxEvents 100 |
Select-Object TimeCreated, Message
```

### Observed Pattern

Network connection events were observed between approximately:

```text
17-09-2026 06:46:16
17-09-2026 07:03:36
```

The displayed output was summarized as:

```text
Network connection detected:...
```

### Interpretation

Network telemetry exists on the endpoint, but the extracted output does not establish communication with a Domain Controller or replication-related infrastructure.

No DCSync conclusion can therefore be based on these generic network events.

---

## 10. Wazuh Investigation

The investigation used the following search pivots:

```text
4662
```

```text
"Replicating Directory Changes"
```

```text
DS-Replication
```

```text
DCSync
```

```text
mimikatz
```

```text
ntds
```

```text
powershell
```

Archived telemetry was also considered:

```text
wazuh-archives-*
```

### Wazuh Event Observation

A Wazuh event was visible with:

```text
_index: wazuh-alerts-4.x-2026.09.17
agent.id: 001
agent.name: DESKTOP-9MMM37V
data.win.eventdata.image:
C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
data.win.eventdata.processId: 20288
```

### Interpretation

This establishes that Wazuh had visibility into a PowerShell process event.

It does **not** establish that the PowerShell process performed DCSync.

The event should therefore be treated as supporting process telemetry rather than a DCSync indicator.

---

## 11. Evidence Correlation

| Artifact | Observation | Assessment |
|---|---|---|
| Host role | WORKGROUP / DomainRole 0 | Standalone workstation |
| OS | Windows 11 Pro | Host identification |
| NTDS service | Not present | No local AD DS service |
| `NTDS.dit` | Not present | Expected on this host |
| Security 4662 | No events | No replication-object telemetry |
| Security 4624 | No events | Authentication unavailable |
| Security 4672 | No events | Privileged-logon context unavailable |
| Sysmon EID 1 | Multiple events | Process telemetry available |
| Sysmon EID 3 | Multiple events | Network telemetry available |
| Wazuh | PowerShell event visible | Process visibility |
| DCSync evidence | Not established | Insufficient evidence |

---

## 12. Investigation Assessment

### Confirmed

- The endpoint is a standalone Windows workstation.
- The endpoint is not a Domain Controller.
- No NTDS service was identified.
- No local `NTDS.dit` file was identified.
- Sysmon process and network telemetry were available.
- Wazuh provided visibility into at least one PowerShell process event.

### Not Confirmed

- DCSync activity.
- Directory replication access.
- Unauthorized replication privileges.
- Credential extraction through Active Directory replication.
- Communication with a Domain Controller for replication purposes.

### Telemetry Limitations

- Security Event ID 4662 was unavailable.
- Security Event ID 4624 was unavailable.
- Security Event ID 4672 was unavailable.
- Sysmon output was summarized and did not provide sufficient fields for attribution.
- The endpoint was not an Active Directory Domain Controller.

## Final Assessment

> **DCSync activity was not confirmed.**

The available evidence supports a conclusion of **insufficient environment and telemetry for DCSync confirmation**, rather than evidence of successful or unsuccessful credential theft.
