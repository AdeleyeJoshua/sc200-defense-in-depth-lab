# Logic App Authorization: Graph API Permission vs. Directory Role

## Finding
The Logic Apps in this project (Scenario 1 and Scenario C, both calling Microsoft Graph to disable a user and revoke sign-in sessions) are ultimately authorized via the built-in Entra ID **User Administrator** directory role, assigned directly to each Logic App's system-assigned managed identity -- not via the originally intended Microsoft Graph `User.ReadWrite.All` **application permission**.

## What Actually Happened
The original design called for granting the managed identity the `User.ReadWrite.All` Graph application permission via Microsoft Graph PowerShell (`New-MgServicePrincipalAppRoleAssignment`). This is the narrower-scoped, generally recommended approach for an automation that only needs to call specific Graph endpoints. Setting this up hit real friction during the build (PowerShell/Graph SDK connection and role-assignment steps did not go smoothly under time pressure), and was replaced with a simpler alternative: assigning the User Administrator directory role directly to the managed identity through the Entra ID portal. This role inherently carries the rights needed to disable a user and revoke sessions, and the Logic Apps functioned correctly once it was assigned.

## Why This Is a Real Tradeoff, Not Just a Simpler Path
Directory roles like User Administrator are broad and standing -- assigning one to a managed identity gives that identity administrative rights over *any* non-privileged user in the entire tenant, indefinitely, not just the ability to call the two specific Graph endpoints this automation actually uses. The Graph application permission approach, while requiring more setup effort, is the more narrowly-scoped, more auditable, and more defensible choice from a least-privilege standpoint -- it grants exactly the API capability needed and nothing more.

This project used the directory role because it was the pragmatic choice under real time constraints, not because it is the better-designed option. That distinction is worth being explicit about rather than letting the simpler path be mistaken for the correct one.

## Takeaway
When automation setup friction leads to choosing a broader permission model over a narrower one, document that choice honestly as a tradeoff, including what the more secure alternative would have been and why it wasn't used. A functioning shortcut is not the same thing as a well-architected solution, and conflating the two in documentation misrepresents the actual security posture of the build.
