# RDP Access to an Entra ID Joined VM

## Finding
The Azure Portal's default downloaded `.rdp` file does not support Entra ID authentication out of the box, and the connecting client machine itself must be Entra ID registered or joined.

## Requirements Found Through Testing
1. **Server-side:** the `AADLoginForWindows` VM extension must be installed and provisioned (`Succeeded`), and the connecting user must hold the `Virtual Machine User Login` (or `Administrator Login`) RBAC role scoped to the VM.
2. **Client-side:** the machine initiating the RDP connection must itself be Microsoft Entra registered, joined, or hybrid joined to the same directory as the target VM. Attempting RDP from an unjoined/unregistered client will not offer Entra ID authentication as an option at all, regardless of server-side configuration.
3. **RDP file properties:** the default file downloaded from the Azure Portal's Connect blade only contains minimal connection properties. Entra ID authentication requires adding, at minimum:
   ```
   enablerdsaadauth:i:1
   ```
   Attempting to force this by disabling CredSSP (`enablecredsspsupport:i:0`) without `enablerdsaadauth:i:1` will instead break Network Level Authentication and produce a distinct connection error (`0xb09`).
4. **Windows App (formerly Remote Desktop) does not currently support direct RDP connections to Azure VMs** — attempting to add a VM connection through it returns "coming soon... use Remote Desktop Connection" — `mstsc.exe` with a correctly configured `.rdp` file is the working path.

## Takeaway
Entra ID authentication for RDP has requirements at three separate layers (server extension + RBAC, client join state, and RDP file properties), and a failure at any one layer produces a different, sometimes misleading error. Diagnosing "logon attempt failed" required checking each layer independently rather than assuming a single cause.
