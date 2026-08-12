# Sysmon Event ID 12 vs 13

## Finding
Registry *value* modifications (e.g. `reg add` targeting an existing key) log as Sysmon Event ID 13 (RegistryEvent — Value Set), not Event ID 12 (RegistryEvent — Object Create/Delete, which only fires for creating or deleting a registry *key* itself).

## How This Was Found
An initial query targeting Event ID 12 for a registry Run-key persistence test returned no matching results for the actual test action. Broadening the query without the specific target filter surfaced an unrelated, legitimate Event ID 12 entry (the Windows Print Spooler service performing routine driver registry maintenance, running as SYSTEM) — which was initially, incorrectly assumed to be the test event itself, leading to a lengthy but ultimately unnecessary investigation into why "the wrong user" appeared to be involved. Cross-referencing `ProcessGuid` values confirmed this Event ID 12 entry was unrelated to the actual test action. Correctly filtering for Event ID 13 instead immediately surfaced the real event, with correct attribution and the expected `RuleName: T1060,RunKey` MITRE tag.

## Takeaway
When hunting for a specific registry action, verify the Event ID against the actual operation type (key create/delete vs. value set) rather than assuming; and when a query for an expected event returns no results, broadening the query without also tightening the target filter can surface unrelated legitimate activity that looks superficially similar, leading to a false lead.
