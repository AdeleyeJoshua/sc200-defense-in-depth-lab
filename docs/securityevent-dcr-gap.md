# Data Collection Rule Scope Gap — Missing Windows Security Event Logs

## Finding
This environment's Data Collection Rule was configured to collect only the `Microsoft-Windows-Sysmon/Operational!*` event channel. Windows Security Event logs — needed for EventID 4624 (logon) and 4698 (scheduled task creation) correlation — were never included, resulting in the `SecurityEvent` table being completely empty in this workspace.

## How This Was Found
Discovered mid-project, during the DFIR walkthrough, when a query for EventID 4624 (RDP logon) returned no results even across a 24-hour window. Checking `SecurityEvent | take 5` directly confirmed the table had no data at all, ruling out a query-logic issue. Reviewing the DCR's configured data sources confirmed only the Sysmon channel had ever been added.

## Impact
- Step 1 of the DFIR walkthrough (validating initial RDP access via EventID 4624) could not be completed as originally planned; Entra ID `SigninLogs` was used as an equivalent substitute.
- The reference persistence run's scheduled task detection (EventID 4698) could not be validated in this environment; registry-based persistence detection (Sysmon EventID 13) was used as the primary evidence for that scenario instead.

## Takeaway
"Windows telemetry is flowing" is not a single fact to verify once — Sysmon and Windows Security Event logs are separate collection channels within the same Data Collection Rule, and confirming one is working says nothing about the other. Each intended data source should be explicitly validated with a direct query before building detections that depend on it.
