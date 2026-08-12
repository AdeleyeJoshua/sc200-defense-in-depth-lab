# Executive Summary

## Project Overview

This project builds and tests a defense-in-depth SOC architecture against a simulated identity-to-endpoint intrusion, using Microsoft Sentinel, Entra ID Conditional Access, and Azure-native automation (Logic Apps). Rather than modeling a single attack chain with one response point at the end — the structure of the original lab syllabus this project began from — this build deliberately tests containment at four independent layers, plus one layer tested specifically to demonstrate where it fails, and one fully uncontained reference run showing what remains for forensics if every layer is bypassed.

## The Core Design Principle

A real SOC does not get one opportunity to stop an intrusion. Every layer of a real environment — identity, cloud application access, endpoint logon, process execution — represents an independent chance to interrupt an attacker, and no single layer can be assumed to always work. This project treats that principle as something to be demonstrated empirically, not just described: several scenarios exist specifically because an earlier layer's control was found, through direct testing, not to cover a particular access path.

## What Was Built

| Layer | Scenario | Result |
|---|---|---|
| Identity | 1 | Password spray detected and the compromised account automatically disabled and session-revoked within one detection cycle |
| Cloud application access | A | Conditional Access successfully blocked sign-in from an untrusted location, before any Sentinel incident was generated |
| VM logon (Conditional Access) | B | Both location-based and risk-based Conditional Access were found, through direct empirical testing, to be structurally unable to evaluate RDP-to-Entra-joined-VM sign-ins — documented as a genuine architectural limitation |
| VM logon (SOAR) | C | A behavioral correlation rule successfully detected and contained the exact access path Scenario B could not gate, closing that gap |
| Execution | 3 | Encoded PowerShell execution was detected with correct user attribution (after resolving a real investigative dead-end) and contained using a three-part response that preserved analyst access and forensic integrity, rather than the simpler but more destructive option of restarting the VM |
| Persistence (reference) | — | Left deliberately uncontained, to demonstrate what an analyst would find during forensic review if every automated layer above had failed |

## Findings That Mattered Most

**Conditional Access has a real, structural blind spot for RDP-to-Entra-joined-VM access.** Neither location-based nor risk-based Conditional Access can evaluate this specific sign-in flow, because Entra ID's telemetry for this access path always reflects the VM's own fixed network position, never the connecting client's real location — confirmed directly by testing through a VPN and observing no change in the logged IP or location. This is not a configuration gap; it is a property of how this authentication flow works, and it is the reason Scenario C exists as an independent, necessary layer.

**Disabling an identity does not terminate an already-active session.** This was independently observed in both Scenario C and Scenario 3: revoking an account's sign-in sessions via Microsoft Graph stops future authentication, but a session already established before that action runs continues uninterrupted until something explicitly ends it. This directly shaped Scenario 3's response design, which includes forced session termination as a distinct, necessary action rather than relying on identity-layer actions alone.

**Attribution in raw telemetry requires verifying against the event's actual payload, not its summarized or top-level fields.** A process's true acting user is sometimes reported incorrectly by a table's default columns, and two plausible-sounding explanations for an observed anomaly were tested and disproven before the real, simpler cause (an unrelated background event sharing the same Event ID) was found by cross-referencing `ProcessGuid` values directly. This same discipline — verify against raw data before accepting a plausible explanation — recurred throughout the project, including catching an incorrect application ID that would have silently prevented Scenario C's detection rule from ever firing.

**Environment configuration gaps can be silent and easy to miss.** A licensing limitation specific to this tenant's Microsoft 365 Developer SKU meant Defender for Endpoint never functioned despite appearing enabled, requiring systematic elimination (service status, event logs, registry values, license assignment) rather than a single configuration fix to diagnose. Separately, a Data Collection Rule scoped only to Sysmon telemetry silently meant Windows Security Event logs were never collected, discovered only mid-investigation during the DFIR walkthrough.

## Why This Matters Beyond the Lab

The value of this project is not that every control worked — it is that every control was actually tested, including the ones that didn't work, and each finding was investigated to a genuine root cause rather than accepted at face value or worked around silently. Scenario B in particular represents a stronger technical result than a scenario that simply succeeded would have: it demonstrates the ability to recognize when a control is structurally inapplicable, explain why, and design the correct alternative layer to close the resulting gap — which is precisely the kind of judgment a real security operations role requires.

## Environment Note

This build relies entirely on Sysmon and Microsoft Sentinel for endpoint telemetry, and on Azure-native (NSG, Run Command) and Entra ID-native (Graph API) mechanisms for containment, due to a tenant-level Defender for Endpoint licensing limitation identified early in the project. Full diagnostic detail is provided in `docs/mde-licensing-diagnosis.md`.
