# windows-dcsync-activity-investigation-lab

## Overview

DCSync is an Active Directory credential-access technique in which an account abuses directory replication permissions to request credential-related data from a Domain Controller as though it were performing legitimate replication.

From a SOC/DFIR perspective, the key evidence is therefore directory replication activity, especially unusual replication requests originating from an unexpected account or host.

The investigation should focus on:

Replication-related Windows Security events.
The account performing the operation.
The source workstation or IP.
Requested directory objects.
Privileged replication permissions.
Process and command-line telemetry.
Correlation with authentication activity.
Wazuh visibility and alerting.
Distinguishing legitimate AD replication from suspicious replication requests.

This lab investigates **DCSync-related activity from a SOC and DFIR perspective** by examining Windows host role, Active Directory-related artifacts, Security events, Sysmon telemetry, and Wazuh visibility.

The investigation was performed on a Windows 11 Pro workstation that was identified as a standalone **WORKGROUP** system rather than an Active Directory Domain Controller.

Because the endpoint was not a Domain Controller, the lab did not attempt to generate or simulate genuine DCSync activity. Instead, the investigation focused on validating the expected artifacts and documenting the telemetry limitations that prevented a DCSync conclusion.

## Investigation Objectives

- Verify whether the investigated Windows endpoint is capable of participating in Active Directory replication.
- Identify the presence or absence of the **NTDS** service and related Active Directory components.
- Check for the expected `NTDS.dit` database artifact and document its status.
- Investigate Windows Security Event ID **4662** for directory-object access activity.
- Search specifically for **directory replication-related access** within available security telemetry.
- Examine authentication events such as **4624** and **4672** for supporting account and privilege context.
- Review **Sysmon Event ID 1** for processes potentially associated with suspicious credential-access activity.
- Review **Sysmon Event ID 3** for network activity that may provide additional investigation context.
- Use Wazuh to search for DCSync, replication, NTDS, and related telemetry.
- Compare Wazuh alert data with archived events to identify potentially unalerted activity.
- Correlate account, process, network, and security-event evidence before making an assessment.
- Identify telemetry and environmental limitations that prevent reliable DCSync attribution.
- Practice distinguishing **confirmed evidence, supporting evidence, and unverified indicators** during a credential-access investigation.# Environment

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

A SOC analyst receives an investigation lead involving possible credential-access activity on a Windows endpoint. The activity is considered potentially related to **DCSync**, an Active Directory technique that can be abused to obtain directory credentials through replication requests.

Before drawing any conclusions, the analyst needs to determine whether the endpoint belongs to an Active Directory environment and whether the expected supporting artifacts are available.

The investigation focuses on:

- Establishing the endpoint's domain and host role.
- Checking for Active Directory-related artifacts.
- Reviewing Windows Security events for relevant authentication and directory-access activity.
- Examining Sysmon process and network telemetry.
- Searching Wazuh for DCSync and replication-related indicators.
- Determining whether the available evidence is sufficient to support the DCSync hypothesis.

The endpoint provides some process and network telemetry, but important Active Directory and Security event data may be unavailable. The analyst must therefore distinguish between relevant investigation leads and evidence that can actually support a DCSync conclusion.

The scenario emphasizes evidence-based investigation, accurate scoping, and documenting telemetry limitations rather than assuming that every suspicious-looking process or network event represents malicious activity.

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

