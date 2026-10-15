# Offboarding-HTTPTrigger1 Summary
Executes initial offboarding automtion triggered by Jira

## Steps
1. Connect to Jira - Done
2. Get Details - Done
3. Validate Inputs - Done
4. Disable Account - Done
5. Revoke Sign In Sessions - Done
7. Revoke Authentication Methods - Done
8. Webex Phone Forwarding - Done
9. Update Core Fields - Done
10. Set Custom Security Attributes - Done
11. Remove Groups - Done
12. Covert to Shared Mailbox - Done
13. Assign Mailbox Access - Done
14. Assign OneDrive Access - Done
15. Send Manager Email - Done
16. Create Sub-task Ticket - Done

# To-Do Notes
## Questions

## New Items
- Validate Inputs should validate any parameters from the ticket webhook that may cause downstream failures. "Fail Fast" methodology.
- Update Core Fields should set the end date for all users. This can be used to look for expiring users instead of a table queue.
- Set ticket in user custom security attributes should allow us to update the ticket in the future without having to keep a table queue with this information. 
- Set Data Expiry in user custom security attributes. Default is 6 months.
  - Will not provide an override on the offboarding form.
- Should we send the manager a summary email instead of seperate emails from Mailbox and OneDrive steps? Yes
- Should revisit if PNP PowerShell is still the best tool for OneDrive Permissioning - PNP PowerShell is still required if manager access is needed for more than 90 days. This is due to PNP PowerShell being the only programmatic method that can manage site collection administrators; without a licensed site collection adminstrator, OneDrive will automatically engage in retention activites starting 60 days after license removal. 
- Should investigate if Entra Lifecycle Workflows can offload any or all of this automation - No, Requires additional licensing. 
- Need to add Exchange Online to Function App's capabilities
  - Add the module to requirements.psd1 - Done.
  - Add AppRoleAssigment - Done
  - Assign RBAC Role - Done
  - Initiate connection - Done
- We are going to eliminate the manager field from the intake form to avoid mismatches between Entra and Jira.
- Subtask generation - Done
  - Need to add DueDate and Assignee to webhook
  - Need to align custom field ids 