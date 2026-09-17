# Timeline — DCSync Activity Investigation

## Timeline Overview

This timeline records the observable investigation activity from the Windows endpoint on **17 September 2026**.

Only events and observations supported by the collected output are included.

---

| Time | Event | Source | Interpretation |
|---|---|---|---|
| 06:46:16 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:48:23 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:50:28 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:52:30 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:52:42 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:54:40 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:56:41 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:57:42 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 06:59:20 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 07:00:50 | Process Create observed | Sysmon Event ID 1 | Process telemetry available |
| 07:01:01–07:03:15 | Multiple Process Create events | Sysmon Event ID 1 | Process telemetry available |
| 07:01:29 | Multiple network connections | Sysmon Event ID 3 | Generic network telemetry |
| 07:03:36 | Network connection detected | Sysmon Event ID 3 | Generic network telemetry |
| 07:10:21 | Investigation timestamp captured | PowerShell | Recorded investigation reference time |

---

## Host Validation

### Host Role

The endpoint reported:

```text
Name        : DESKTOP-9MMM37V
Domain      : WORKGROUP
DomainRole  : 0
```

### Finding

The machine was confirmed as a standalone workstation rather than a Domain Controller.

---

## NTDS Artifact Validation

### NTDS Service

The `NTDS` service query returned no service.

### NTDS.dit

The database check returned:

```text
False
```

for:

```text
C:\Windows\NTDS\ntds.dit
```

### Finding

No local Active Directory database or NTDS service was identified.

---

## Security Log Investigation

### Event ID 4662

No matching events were found.

### Replication-Related 4662 Search

No matching replication-related events were found.

### Event ID 4624

No matching events were found.

### Event ID 4672

No matching events were found.

### Finding

The required Security telemetry for correlating a DCSync hypothesis was unavailable.

---

## Sysmon Investigation

### Event ID 1

Multiple Process Create events were observed.

The available output did not provide enough detail to attribute any process to DCSync.

### Event ID 3

Multiple Network Connection events were observed.

The available output did not provide sufficient source, destination, process, or port information to associate the connections with Active Directory replication.

---

## Wazuh Investigation

Wazuh provided visibility into a PowerShell process event.

Observed fields included:

```text
agent.id:
001

agent.name:
DESKTOP-9MMM37V

image:
C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

processId:
20288
```

### Finding

The Wazuh event confirms PowerShell process telemetry but does not establish DCSync activity.

---

## Evidence State

```text
Host Role
   |
   +-- WORKGROUP
   +-- DomainRole 0
          |
          v
Not a Domain Controller
          |
          v
No NTDS Service
          |
          v
No NTDS.dit
          |
          v
No Security 4662
          |
          v
No 4624 / 4672
          |
          v
Sysmon Process + Network Telemetry
          |
          v
Insufficient Attribution
          |
          v
DCSync NOT CONFIRMED
```

---

## Final Timeline Assessment

The timeline demonstrates that the endpoint generated normal Sysmon process and network telemetry during the investigation period, while the host itself was confirmed to be a standalone WORKGROUP workstation.

No NTDS service, `NTDS.dit`, Security Event ID 4662, or supporting authentication telemetry was available. The observed Sysmon and Wazuh events therefore could not be correlated strongly enough to establish DCSync activity.

**Final assessment: DCSync activity was not confirmed from the available endpoint evidence.**

## DFIR Note

Generic process and network events remain **contextual evidence** until their relevant fields can be correlated to an account, process, destination, timestamp, and directory-replication operation.

Do not convert telemetry gaps into assumptions.
