# Scenario A — Conditional Access Policy Configuration

This scenario has no detection KQL of its own -- Conditional Access blocks the
sign-in before Sentinel ever generates an incident. The "detection" for this
scenario is the Conditional Access policy configuration itself, plus a
verification query run manually after the fact.

## Policy Configuration
- **Name:** (as configured in tenant)
- **Users:** sjones
- **Target resources:** All cloud apps
- **Conditions:** Locations -- exclude operator's trusted/home location, apply to all others
- **Grant:** Block access
- **State:** On

## Verification Query (run manually, not bound to any automation)

```kusto
SigninLogs
| where UserPrincipalName has "sjones"
| where TimeGenerated > ago(2h)
| where ConditionalAccessStatus == "failure"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, ConditionalAccessStatus, ConditionalAccessPolicies
```

Expand `ConditionalAccessPolicies` in the result to confirm the specific
policy name that enforced the block.

See `reports/scenarioA-timeline.md` for full narrative and reasoning.
