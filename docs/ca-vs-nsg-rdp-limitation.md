# Conditional Access Cannot Gate RDP-to-Entra-Joined-VM Sign-Ins

## Finding
Neither location-based nor risk-based Conditional Access can meaningfully evaluate an RDP sign-in to an Entra ID Joined virtual machine, because this authentication flow does not transmit the connecting client's real network location to Entra ID — only the VM's own fixed network position.

## How This Was Found
A location-based Conditional Access policy was built expecting to block RDP access from an untrusted network. Testing showed the policy never evaluated as expected: the sign-in log's IP address and location always reflected the VM itself, regardless of the actual RDP client's location. This was re-tested deliberately by routing the RDP connection through a VPN exit node in a different country specifically to see whether the sign-in telemetry would change — it did not. The same result was later confirmed for a risk-based Conditional Access policy (Identity Protection User Risk / Sign-in Risk), which also showed `ConditionalAccessStatus: notApplied` and `RiskLevelDuringSignIn: none` under identical VPN-routed test conditions.

## Root Cause
RDP sign-in to an Entra-joined VM is authenticated via the VM's own device identity (Primary Refresh Token), not a proxied representation of the connecting client. Entra ID has no visibility into the RDP client's actual network context for this specific flow.

## Resolution
Location-based Conditional Access was scoped to cloud application access instead (Scenario A), where client IP is correctly transmitted. RDP-to-VM access is instead covered by a separate detection and SOAR response layer (Scenario C), built specifically because Conditional Access cannot cover this access path.

## Takeaway
A control's applicability should be tested against the specific authentication flow in question, not assumed from its general capability. "Conditional Access supports risk-based and location-based policies" does not mean every sign-in flow transmits the telemetry those policies depend on.
