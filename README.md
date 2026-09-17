# Windows DCSync Activity Investigation Lab

## Overview

This lab investigates **DCSync-related activity from a SOC and DFIR perspective** by examining Windows host role, Active Directory-related artifacts, Security events, Sysmon telemetry, and Wazuh visibility.

The investigation was performed on a Windows 11 Pro workstation that was identified as a standalone **WORKGROUP** system rather than an Active Directory Domain Controller.

Because the endpoint was not a Domain Controller, the lab did not attempt to generate or simulate genuine DCSync activity. Instead, the investigation focused on validating the expected artifacts and documenting the telemetry limitations that prevented a DCSync conclusion.

## Investigation Objectives

- Determine whether the endpoint is an Active Directory Domain Controller.
- Check for the presence of the `NTDS` service.
- Check whether `NTDS.dit` exists on the endpoint.
- Investigate Windows Security Event ID 4662 availability.
- Check authentication events such as 4624 and 4672.
- Review Sysmon Process Create and Network Connection telemetry.
- Search Wazuh for DCSync and replication-related indicators.
- Distinguish relevant telemetry from unrelated process and network events.
- Document evidence limitations without fabricating missing events.
- Establish whether DCSync activity can be confirmed from the available evidence.

## Environment

| Component | Observed Value |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| Operating System | Windows 11 Pro |
| Windows Version | `10.0.26200` |
| Domain | `WORKGROUP` |
| Domain Role | `0` |
| NTDS Service | Not present |
| `NTDS.dit` | Not present |
| Sysmon | Available |
| Wazuh Agent | `001` |
| Wazuh Agent Name | `DESKTOP-9MMM37V` |

## Lab Workspace

```text
C:\DCSyncLab
└── Evidence
```

## Scenario

Security monitoring identified activity that could potentially be associated with credential-access techniques involving Active Directory replication.

The investigation therefore examined the endpoint for the infrastructure and telemetry normally required to investigate DCSync activity.

The first step was validating the host role. The system reported `WORKGROUP` and `DomainRole 0`, establishing that it was a standalone workstation rather than a Domain Controller.

The investigation then checked for the `NTDS` service and `NTDS.dit`. Neither was present. Windows Security Event ID 4662 was also unavailable, as were the queried 4624 and 4672 events.

Sysmon Process Create and Network Connection events were available, but the returned output was summarized as generic `Process Create:...` and `Network connection detected:...` messages. The available output did not provide enough fields to attribute those events to DCSync activity.

## Investigation Workflow

```text
Host Role Validation
        |
        v
NTDS Service Check
        |
        v
NTDS.dit Check
        |
        v
Security Event Investigation
        |
        v
Sysmon Process Investigation
        |
        v
Sysmon Network Investigation
        |
        v
Wazuh Investigation
        |
        v
Evidence Correlation
        |
        v
Final Assessment
```

## Key Findings

### 1. Host Role

The system reported:

```text
Name        : DESKTOP-9MMM37V
Domain      : WORKGROUP
DomainRole  : 0
```

This indicates that the endpoint is a standalone workstation.

### 2. NTDS Service

The command:

```powershell
Get-Service NTDS -ErrorAction SilentlyContinue
```

returned no NTDS service.

The broader service search returned unrelated services, but no Active Directory Domain Services service.

### 3. NTDS.dit

The following check returned:

```text
False
```

```powershell
Test-Path "C:\Windows\NTDS\ntds.dit"
```

No files were returned from the `C:\Windows\NTDS` directory query.

### 4. Security Event 4662

The query for Event ID 4662 returned:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

A second query filtering for replication-related terms also returned no events.

### 5. Authentication Events

Queries for:

- Event ID 4624
- Event ID 4672

both returned no matching events.

### 6. Sysmon Process Creation

Sysmon Event ID 1 was available and returned multiple process creation events.

A keyword-filtered query returned events between approximately `07:00` and `07:03` on `17-09-2026`.

However, the available output only displayed:

```text
Process Create:...
```

The summarized output did not establish that these processes performed DCSync or directory replication activity.

### 7. Sysmon Network Connections

Sysmon Event ID 3 returned multiple network connection events between approximately `06:46` and `07:03` on `17-09-2026`.

The available output displayed:

```text
Network connection detected:...
```

The summarized results did not expose sufficient process, destination, port, or account information to associate the connections with DCSync.

## Evidence-Based Assessment

The investigation confirmed that this endpoint is **not a Domain Controller** and does not contain the expected local Active Directory database or NTDS service.

No Security Event ID 4662 records were available, and the queried authentication events were also unavailable.

Sysmon telemetry was present, but the available fields were insufficient to establish DCSync behavior.

Therefore:

> **DCSync activity was not confirmed on this endpoint.**

This conclusion does not mean that DCSync is impossible in the environment. It means that the current endpoint does not provide the required Active Directory environment or telemetry to establish such activity.

## Important DFIR Principle

A process name, network connection, or keyword match should not automatically be treated as proof of DCSync.

A stronger investigation requires correlation between:

```text
Account
   +
Source Host
   +
Authentication
   +
Process
   +
Directory Replication Access
   +
4662 Details
   +
Network Context
```

Missing telemetry should be documented rather than replaced with assumptions.

## Wazuh Investigation

The following searches were used as investigation pivots:

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

Archived telemetry was also considered using:

```text
wazuh-archives-*
```

The purpose was to determine whether relevant events existed without necessarily generating Wazuh alerts.

## Lessons Learned

- Always establish the host role before investigating an Active Directory-specific technique.
- A WORKGROUP workstation should not be treated as a Domain Controller.
- Absence of `NTDS.dit` on a standalone workstation is expected.
- Security Event ID 4662 is useful only when the required auditing and directory environment exist.
- Generic Sysmon events are not automatically evidence of DCSync.
- Wazuh visibility depends on the telemetry collected by the agent.
- Missing events are themselves useful investigation findings.
- DCSync attribution requires multiple correlated artifacts.

## Conclusion

This lab demonstrated how to investigate a DCSync hypothesis without fabricating Active Directory evidence. The endpoint was confirmed to be a standalone Windows workstation with no local `NTDS.dit` database or NTDS service, while the required Security Event ID 4662 telemetry was unavailable. Sysmon provided process and network telemetry, but the available event output was insufficient to associate that activity with DCSync. The investigation therefore concluded that **DCSync activity could not be confirmed from this endpoint**.

## Skills Demonstrated

- Windows DFIR
- Active Directory security concepts
- DCSync investigation methodology
- Windows Event Log analysis
- Sysmon analysis
- Wazuh threat hunting
- Evidence correlation
- Telemetry validation
- Investigation scoping
- Evidence-based conclusions
