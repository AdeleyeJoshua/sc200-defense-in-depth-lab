# Envelope vs Payload User Attribution

## Finding
The generic `Event` table's top-level `UserName` column reflects the security context of the process/service that *wrote* the log entry (frequently `NT AUTHORITY\SYSTEM` for Sysmon-sourced events), not necessarily the user who performed the action being described. Reliable attribution requires extracting the `User` field from inside the event's own payload data (`EventData` / `RenderedDescription`).

## How This Was Found
Running an unfiltered query against Sysmon Event ID 1 (process creation) showed most results attributed to `NT AUTHORITY\SYSTEM` or `NT AUTHORITY\NETWORK SERVICE` — initially concerning, until recognized as expected: most process activity on a Windows Server at any given moment is legitimate background/service activity, not interactive user action. Filtering to the specific test payload (encoded PowerShell) and extracting the payload-level `User` field directly, rather than relying on the table's default column, correctly returned the actual acting user (`sjones`) in every case tested.

## Fix Applied
```kusto
| extend ActualUser = extract(@'<Data Name="User">([^<]+)</Data>', 1, EventData)
```
used consistently across all detection queries in this project in place of the default `UserName` column, along with corresponding entity mapping updates in each analytics rule to map the Account entity to this extracted field.

## Takeaway
Don't trust a table's default/summary columns for attribution without checking whether they reflect the acting subject or the logging mechanism. When in doubt, inspect the raw event payload directly.
