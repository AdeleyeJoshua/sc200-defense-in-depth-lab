# MDE Licensing Diagnosis

## Finding
Microsoft Defender for Endpoint never functioned in this tenant, despite the "Microsoft 365 Defender" service plan appearing enabled under the tenant's Microsoft 365 E5 Developer SKU.

## Diagnostic Trail
1. `Get-Service Sense` — confirmed the MDE sensor service was installed and running.
2. `Microsoft-Windows-SENSE/Operational` event log — confirmed the sensor was authenticating successfully and uploading telemetry (result code `0x0`). One notable log entry: `Policy update: Latency mode - demo` and `Cloud configuration loaded from persistent storage, version: 0.0.0.0` — a signal, in hindsight, that the sensor was running with a placeholder/non-production configuration.
3. Registry `OrgId` (`HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection`) — confirmed populated and matching the tenant's actual Defender workspace ID (this ID is intentionally different from the Entra tenant ID — a separate identifier system).
4. Device Inventory (`security.microsoft.com/machines`) — showed 0 devices, despite all of the above.
5. Per-user license assignment — confirmed "Microsoft 365 Defender" toggled ON for the test user.
6. No self-service Defender for Endpoint trial was available in this tenant's Trials pane (only Defender Vulnerability Management, an add-on requiring an existing MDE license).

## Root Cause
The Microsoft 365 Developer Program's E5 SKU includes several service plan *names* for sandbox/testing purposes without necessarily carrying full underlying entitlement for products with separate seat-based backend provisioning, such as Defender for Endpoint. The sensor can authenticate and upload telemetry generically (that layer is not license-gated), but the backend never formally registers the device without a valid commercial entitlement behind it.

## Decision
Proceeded without Defender for Endpoint for the remainder of the project. Sysmon, forwarded through Azure Monitor Agent into Sentinel, became the sole endpoint telemetry source. All containment actions were redesigned around Azure-native (NSG, Run Command) and Entra ID-native (Microsoft Graph) mechanisms rather than Defender's isolate-device API.
