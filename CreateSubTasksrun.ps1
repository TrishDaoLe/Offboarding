<#
.SYNOPSIS
  Creating sub-tasks tickets linked to the parent ticket
.DESCRIPTION
   Using details from offboarding ticket and the offboarding json file, it will create sub-tickets based on the description and have it linked.
.EXAMPLE
   When triggered through the ticket the automation will send a web request to an Azure Function
#>

using namespace System.Net

param($Request, $TriggerMetadata)

$ErrorActionPreference = 'Stop'
$debugEnabled = $false
$FailRunOnAnyError = $false


function Validate-Inputs {
    # Validate webhook inputs. Check for mandaitory values; check for minimum and maximum values. 
    param([hashtable]$Inputs)

    # --- Declarative validation rules ---
    $ValidationRules = @{
        dueDate        = @{ Min=9; Max=10; Mandatory=$true }
        assignee       = @{ Min=1; Max=256; Mandatory=$true }
    }

    $AllValid = $true
    $failedFields = New-Object System.Collections.ArrayList

    foreach ($field in $ValidationRules.Keys) {
        $rule  = $ValidationRules[$field]
        $value = $Inputs[$field]

        # Resolve conditional mandatory
        $isMandatory = $false
        if ($rule.ContainsKey('Conditional')) {
            try {
                $isMandatory = $($rule.Conditional).Invoke($Inputs)
            } catch {
                Write-Log -Message "Fatal Error: Conditional evaluation failed for $field : $($_.Exception.Message)" -level "Error" -Activity "Validate Inputs"
                $AllValid = $false
                $failedFields.Add($field)
            }
        } else {
            $isMandatory = [bool]$rule.Mandatory
        }

        # Normalize to string for length checks (but don't force non-strings)
        $stringValue = if ($null -ne $value) { [string]$value } else { $null }

        # Mandatory check
        if (($isMandatory) -and ([string]::IsNullOrWhiteSpace($stringValue))) {
            Write-Log -Message "Fatal Error: $field is mandatory but missing" -level "Error" -Activity "Validate Inputs"
            $AllValid = $false
            $failedFields.Add($field)
            continue
        }

        # Length checks
        if ($stringValue){
            if (($rule.ContainsKey('Min')) -and ($null -ne $stringValue) -and ($stringValue.Length -lt $rule.Min)) {
                Write-Log -Message "Fatal Error: $field is shorter than minimum length $($rule.Min)" -level "Error" -Activity "Validate Inputs"
                $AllValid = $false
                $failedFields.Add($field)
            }
            if (($rule.ContainsKey('Max')) -and ($null -ne $stringValue) -and ($stringValue.Length -gt $rule.Max)) {
                Write-Log -Message "Fatal Error: $field exceeds maximum length $($rule.Max)" -level "Error" -Activity "Validate Inputs"
                $AllValid = $false
                $failedFields.Add($field)
            }
        }

        # Allowed values
        if (($rule.ContainsKey('Allowed')) -and ($null -ne $value)) {
            if ($value -notin $rule.Allowed) {
                Write-Log -Message "Fatal Error: $field value '$value' is invalid. Allowed values: $($rule.Allowed -join ', ')" -level "Error" -Activity "Validate Inputs"
                $AllValid = $false
                $failedFields.Add($field)
            }
        }
    }
    return [PSCustomObject]@{AllValid=$AllValid; FailedFields=$failedFields}
}


function Add-JiraSubtasks {
    param (
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$Ticket,
        [Parameter(Mandatory)][string]$DueDate,
        [Parameter(Mandatory)][string]$Assignee,
        [Parameter(Mandatory)][string]$businessUnit,
        [Parameter()][int]$MaxAttempts = 5,
        [Parameter()][int]$SleepSeconds = 2
    )

    $tasksFailed = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    #$fieldBusinessUnit = $env:jira_field_BusinessUnit
    $fieldRequestParticipants = $env:jira_field_RequestParticipants
    $fieldRequestType = $env:jira_field_RequestType
    $fieldSubTaskDeadline = $env:jira_field_SubTaskDeadline
    $itemRequestTypeId = $env:jira_item_OffboardRequestTypeId
    $jiraUrl = $env:jira_Server
    $jiraSvcUsername = $env:jira_svcaccount_Username
    $jiraSvcId = $env:jira_svcaccount_Id

    $taskConfigPath = Join-Path $PSScriptRoot $env:jira_SubTasks_Config
    $tasks = Get-Content -Path $taskConfigPath -Raw | ConvertFrom-Json
    
    # Get an authorization header for Jira REST API 
    try {
        $headers = Get-JiraAuthHeader -JiraUser $env:jira_SvcAccount_Username -ApiToken $env:jira_SvcAccount_APIToken
    }
        catch {
            throw "Unable to retrieve Jira authorization header: $($_.Exception.Message)"
        }
    if (-not $headers){
        throw [InvalidOperationException]::new("Get-JiraAuthHeader did not return a successful result.")
    }
    # Get the offboarding user from Entra
    try {
        $mgUser = get-mguser -userid $userid -property DisplayName,employeeType,UserPrincipalName
    }
        catch {
            throw "Unable to retrieve Entra user: $($UserId): $($_.Exception.Message)"
        }
    # Get the offboarding user's manager from Entra
    try {
        $userManager = get-mgusermanager -userid $UserId
        $mgManager = get-mguser -userid $userManager.id -property DisplayName,mail
    }
        catch {
            throw "Unable to retrieve Entra manager $($_.Exception.Message)"
        }
    # Get all Jira users for client-side filtering. Server-side filtering is not reliable for searching on properties other than account id. 
    $url = $jiraUrl + "/rest/api/3/users/search?maxResults=1000"
    try {
        $jiraUsers = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
    }
        catch {
            throw "Unable to retrieve Jira users: $($_.Exception.Message)"
        }
    # Requires at least PowerShell 7, executes iterations in parallel    
    $tasks | foreach-object -parallel {
        # Need to forcibly re-import any non managed modules
        Import-Module HelpdeskAutomation -WarningAction SilentlyContinue
        # Store the pipeline input as a local variable. This will be useful when the pipeline becomes overwritten with where-object filtering on jiraUsers.
        $item = $_
        # Likely not neccessary since the loop iteration operates in its own execution space. Copilot believes PowerShell can reuse runspaces.
        $description = $null
        $issue = $null  
        $issueKey = $null 
        $linkCreated = $false
        $newIssue = $null 
        $newLink = $null
        $subTaskAssignee = $null
        $subTaskReporter = $null
        # Pull in varaibles from outside the loop. 
        $businessUnit = $using:businessUnit
        $assignee = $using:Assignee
        $dueDate = $using:dueDate
        $headers = $using:headers
        $jiraSvcId = $using:jiraSvcId
        $jiraSvcUsername = $using:jiraSvcUsername
        $jiraUsers = $using:jiraUsers
        $mgManager = $using:mgManager
        $mgUser = $using:mgUser
        $tasksFailed = $using:tasksFailed
        $ticket = $using:Ticket
        $fieldRequestType = $using:fieldRequestType
        $fieldRequestParticipants = $using:fieldRequestParticipants
        $fieldSubTaskDeadline = $using:fieldSubTaskDeadline
        $itemRequestTypeId = $using:itemRequestTypeId
        $jiraUrl = $using:jiraUrl
        $MaxAttempts = $using:MaxAttempts
        $SleepSeconds = $using:SleepSeconds

        # Filter tasks based on Buisness Unit. Can use EmployeeType ($item.EmployeeType -contains $mgUser.employeeType) later to filter on employee type.
        if ($item.BusinessUnit -contains $businessUnit){
            # Craft full task name
            $taskName = "Employee Seperation: $($mgUser.DisplayName) $dueDate | $($item.TaskName)"
            if ($item.Assignee){
                if ($item.Assignee -eq "HelpDesk"){
                    # If "HelpDesk" is set as the Assignee, use the parent ticket assingee. Assignee must be in the format of Jira account id, filter based on EmailAddress but use the account id. Fall back to service account id if neccessary.
                    $subTaskAssignee = $jiraUsers | where {($_.EmailAddress -eq $Assignee) -or ($_.AccountId -eq $Assignee) } | Select-Object -First 1
                    if ($subTaskAssignee.AccountId){
                        #write-log -Message "AccountId found for $($subTaskAssignee.EmailAddress): $($subTaskAssignee.AccountId)" -Level "Information" -Activity "Create Jira Subtasks"
                        $subTaskAssignee = $subTaskAssignee.AccountId
                    }
                        else {
                            # If no AccountId found for the Jira user, default to service account id
                            $subTaskAssignee = $jiraSvcId
                            #write-log -Message "Unable to look up Jira user $($Assignee) for Assignee. Using $($jiraSvcUsername) for Assignee instead." -Level "Information" -Activity "Create Jira Subtasks"
                        }
                    }
                    else {
                        # If "HelpDesk" is not set as the Assignee, then use value provided. Assignee must be in the format of Jira account id, filter based on EmailAddress or AccountId but use the Account Id.
                        $subTaskAssignee = $jiraUsers | where {($_.EmailAddress -eq $item.Assignee) -or ($_.AccountId -eq $item.Assignee) } | Select-Object -First 1
                        if ($subTaskAssignee.AccountId){
                            #write-log -Message "AccountId found for $($subTaskAssignee.EmailAddress): $($subTaskAssignee.AccountId)" -Level "Information" -Activity "Create Jira Subtasks"
                            $subTaskAssignee = $subTaskAssignee.AccountId
                        }
                            else {
                                # If no AccountId found for the Jira user, default to service account id
                                $subTaskAssignee = $jiraSvcId
                                #write-log -Message "Unable to look up Jira user $($item.Assignee) for Assignee. Using $($jiraSvcUsername) for Assignee instead" -Level "Information" -Activity "Create Jira Subtasks"
                            }
                }
            }   
                else {
                    # If no Assignee, default to service account id
                    $subTaskAssignee = $jiraSvcId
                }
            if ($item.Reporter){
                # Reporter must be in the format of Jira account id, filter based on EmailAddress or AccountId but use the Account Id. 
                $reporter = $jiraUsers | where {($_.EmailAddress -eq $item.reporter) -or ($_.AccountId -eq $item.reporter)} | Select-Object -First 1
                if ($reporter.AccountId){
                    #write-log -Message "AccountId found for $($reporter.EmailAddress): $($reporter.AccountId)" -Level "Information" -Activity "Create Jira Subtasks"
                    $subTaskReporter = $reporter.AccountId
                }
                    else {
                        # If no AccountId found for the Jira user, default to service account id
                        $subTaskReporter = $jiraSvcId
                        #write-log -Message "Unable to look up Jira user $($item.Reporter) for Reporter. Using $($jiraSvcUsername) for Reporter instead." -Level "Information" -Activity "Create Jira Subtasks"
                    }
            }
                else {
                    # If no Reporter, default to service account id
                    $subTaskReporter = $jiraSvcId
                }
            $requestParticipants = @()
            if ($item.RequestParticipants){
                # Request Participants must be in the format of Jira account id stored in an array; filter based on account id or email address. Leave empty if neccessary.
                foreach ($rp in $item.RequestParticipants) {
                    $requestParticipant = $null
                    $requestParticipant = $jiraUsers | where {($_.EmailAddress -eq $rp) -or ($_.AccountId -eq $rp)} | Select-Object -First 1
                    if ($requestParticipant.AccountId) {
                        $requestParticipants += @{ accountId = ($requestParticipant.AccountId) }
                    }
                        else {
                            #write-log -Message "Unable to look up Jira user $($item.RequestParticipants) for Request Participants. This will be left blank." -Level "Information" -Activity "Create Jira Subtasks"
                        }
                }
            }

            if ($item.DueDateOffset){
                # The due date may be offset from the parent ticket due date either in days backwards or fowards; only business days should be considered. 
                $subTaskDeadline = Add-BusinessDays -StartDate $dueDate -DaystoAdd $item.DueDateOffset
            }
                else {
                    $subTaskDeadline = $dueDate
                }
            # The variable should be cast as a DateTime for later string reformating. Add 17 hours to make the time 5 PM. 
            $subTaskDeadline = ([datetime]$subTaskDeadline).Date.AddHours(17)
            
            # Apply dynamic values to the end of the task description
            $addendum = @"


                
Task: $($item.TaskName)
User: $($mgUser.DisplayName)
Email: $($mgUser.UserPrincipalName)
Manager: $($mgManager.DisplayName)
Offboarding Date: $(([datetime]$DueDate).ToString('MMM d, yyyy'))
Task Due: $($subTaskDeadline.ToString('MMM d, yyyy h tt'))
"@
            $description = $item.Description + $addendum

            # Craft the body for the REST API POST
            $body = @{
                fields = @{
                    project = @{
                        key = "HS"
                    }
                    issuetype = @{
                        name = "Task"
                    } 
                    summary = $taskName
                    assignee = @{
                        accountId = $subTaskAssignee
                    }
                    reporter = @{
                        accountId = $subTaskReporter
                    }
                    duedate = $subTaskDeadline.ToString("yyyy-MM-dd")
                    $fieldRequestType = $itemRequestTypeId
                    $fieldRequestParticipants = $requestParticipants
                    $fieldSubTaskDeadline = $subTaskDeadline.ToString("yyyy-MM-dd")
                    description = @{
                        type    = "doc"
                        version = 1
                        content = @(
                            @{
                                type = "paragraph"
                                content = @(
                                    @{
                                        type = "text"
                                        text = $description
                                    }
                                )
                            }
                        )
                    }
                }
            }  | ConvertTo-Json -Depth 20
            #write-log -Message "Parameters: $($body)" -Level "Debug" -Activity "Create Jira Subtasks"
            # Create the Jira Ticket 
            try {
                $newIssue = Invoke-RestMethod -Uri "$jiraUrl/rest/api/3/issue" -Method Post -Headers $headers -Body $body -ContentType "application/json" -ErrorAction Stop   
            }
                catch {
                    write-log -Message "Unable to create task $($item.TaskName)" -Level "Information" -Activity "Create Jira Subtasks"
                    #write-log -Message "Body: $body" -Level "Information" -Activity "Create Jira Subtasks"
                    $tasksFailed.Add($item.TaskName)
                    return
                }
            # Verify the ticket was created before linking to parent ticket
            $issueKey = $newIssue.key
            for ($i = 1; $i -le $MaxAttempts; $i++) {
                try {
                    $Issue = Invoke-RestMethod -Uri "$jiraUrl/rest/api/3/issue/$issueKey" -Method Get -Headers $headers -ErrorAction Stop
                    if ($null -ne $Issue) {
                        break
                    }
                } catch { }
                if ($i -eq $MaxAttempts){
                    write-log -Message "Unable to verify task $($item.TaskName)" -Level "Information" -Activity "Create Jira Subtasks"
                    $tasksFailed.Add($item.TaskName)
                    return
                }
                Start-Sleep -Seconds $SleepSeconds
            }

            # Link to parent ticket as 'Implements'
            $linkBody = @{
                type = @{
                    name = 'Implements'
                }
                inwardIssue = @{
                    key = $issueKey
                }
                outwardIssue = @{
                    key = $ticket
                }
            } | ConvertTo-Json -Depth 10
            # Retry linking until successful or max attempts. This is done in case there is a transient consistency issue between verifying the new issue exists and attempting the linking
            for ($i = 1; $i -le $MaxAttempts; $i++){
                try {
                    $newLink = Invoke-RestMethod -Uri "$jiraUrl/rest/api/3/issueLink" -Method Post -Headers $headers -Body $linkBody -ContentType "application/json" -ErrorAction Stop
                } catch {}
                Start-Sleep -Seconds $SleepSeconds
                try {
                    $Issue = Invoke-RestMethod -Uri "$jiraUrl/rest/api/3/issue/$issueKey" -Method Get -Headers $headers -ErrorAction Stop
                } catch {}
                $linkCreated = [bool](
                    $Issue.fields.IssueLinks | where {(($_.outwardIssue.key -eq $ticket) -or ($_.inwardIssue.Key -eq $ticket))}
                )
                if ($linkCreated){
                    #write-log -Message "Task: $taskName Created" -Level "Verbose" -Activity "Create Jira Subtasks"
                    break
                }
            }
            if (-not $linkCreated) {
                write-log -Message "Unable to link task $($item.TaskName) to ticket $ticket" -Level "Information" -Activity "Create Jira Subtasks"
                #write-log -Message "Issue Links: $($Issue.IssueLinks | ConvertTo-Json -Depth 10)" -Level "Information" -Activity "Create Jira Subtasks"
                $tasksFailed.Add($item.TaskName)
            }
        }
    } -ThrottleLimit 5 # Throttle limit is how many concurrent parallel threads should be created from the for loop. Balance this between available compute, Jira limits, and function timeout limits.
    if ($tasksFailed.isEmpty) {
        return [pscustomobject]@{ Status="Completed"; Message="All tasks created and linked."}
    }
        else {
            $failedTasks = $tasksFailed.ToArray()
            Write-Log -Message "Failed to create or link the following tasks: $($failedTasks -join ', ')" -Level "Information" -Activity "Create Jira Subtasks"
            return [pscustomobject]@{ Status="Failed"; Message="$($tasksFailed.Count) tasks failed to be created or linked." }
        }
}



Write-Log -Message "===IT Offboarding Runbook Started ===" -Level "information"

# Parse webhook JSON

# Normalize request to a PSObject
$raw = $Request.Body
#test
$rawBody = $Request.RawBody
write-log -level "Debug" -Activity "Parse Webhook" -Message $rawBody -debug # [Debug][Parse Webhook] System.Management.Automation.OrderedHashtable

# Convert byte[] to string if needed
if ($raw -is [byte[]]) {
    $raw = [System.Text.Encoding]::UTF8.GetString($raw)
}

# If it's JSON text, convert it
if ($raw -is [string]) {
    try {
        $WebhookJSON = $raw | ConvertFrom-Json
    }
    catch {
        Write-Log -Activity "Parse Webhook" -Level "Error" -Message "Invalid JSON body: $($_.Exception.Message)"
        return (New-Object -TypeName HttpResponseContext -Property @{
            StatusCode = 400
            Body       = "Bad or malformed JSON."
        })
    }
}
    elseif ($raw -is [pscustomobject] -or $raw -is [hashtable]) {
        # Already parsed by Azure
        $WebhookJSON = $raw
    }
    else {
        Write-log -Activity "Parse Webhook" -Level "Error" -Message "Unsupported request body type: $($raw.GetType().FullName)"
        return (New-Object -TypeName HttpResponseContext -Property @{
            StatusCode = 400
            Body       = "Unsupported request body type."
        })
    }

# At this point, $WebhookJSON is ALWAYS a PSObject — safe to access properties
$Script:Ticket       = $WebhookJSON.key
 
if ($WebhookJSON.debugEnabled -is [bool]){
    $debugEnabled = $WebhookJSON.debugEnabled
}
if ($WebhookJSON.failRunOnAnyError -is [bool]){
    $FailRunOnAnyError = $WebhookJSON.failRunOnAnyError
}

$DebugPreference = if ($DebugEnabled) { 'Continue' } else { 'SilentlyContinue' }

Write-Log -Message "Webhook JSON parsed" -Activity "Parse Webhook" -level "Verbose"    
write-log -Message "$WebhookJSON" -Activity "Parse Webhook" -level "Debug"
Write-Log -Message "Jira Ticket: $Ticket" -Activity "Parse Webhook" -Level "Verbose"
Write-Log -Message "Debug Enabled: $debugEnabled" -Activity "Parse Webhook" -level "Verbose"
Write-Log -Message "Fail Run On Any Error: $FailRunOnAnyError" -Activity "Parse Webhook" -level "Verbose" 

# 1) Connect to Jira Service Management
Set-Step -Name "Connect to Jira Service Management" -Status "Started"
try {
    Connect-JiraPS
} 
    catch {
        Set-Step -Name "Connect to Jira Service Management" -Message "Connection failure" -Status "Failed" -Ticket $Ticket
        Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "Information" -Ticket $Ticket
        return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Connect to Jira Service Management Failed"
        })
    }
Set-Step -Name "Connect to Jira Service Management" -Message "Jira connected" -Status "Completed" -Ticket $Ticket

# 2) Derive Offboarding Details
Set-Step -Name "Derive Offboarding Details" -Status "Started"
try {
    $upn            = $WebhookJSON.offboarduseremail
    $phoneForwardingUser = $WebhookJSON.phoneForwarding
    $additionalMembers = $WebhookJSON.additionalMembers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    
    $password       = Get-RandomPassword -PasswordLength 12

    #Need to add to webhook
    $assignee = $WebhookJSON.assignee
    $dueDate = ([datetime]$WebhookJSON.dueDate).ToString('MM/dd/yyyy')
    $businessUnit = $WebhookJSON.businessUnit

    $dataExpiry = Get-date (Get-Date $dueDate).AddDays(180) -format "MM/dd/yyyy"
} 
    catch {
        Set-Step -Name "Derive Offboarding Details" -Message "Failed to derive identity: $($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "Information" -Ticket $Ticket
        return (New-Object -TypeName HttpResponseContext -Property @{
            StatusCode = 400
            Body       = "Derive Offboarding Details Failed"
        })
}
Set-Step -Name "Derive Offboarding Details" -Status "Completed" -Ticket $Ticket

# 3) Validate Inputs
Set-Step -Name "Validate Inputs" -Status "Started"
try {
    $valid = Validate-Inputs -Inputs @{
        
        dueDate = $dueDate
        assignee = $assignee
    }
} 
    catch {
        Set-Step -Name "Validate Inputs" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
        return (New-Object -TypeName HttpResponseContext -Property @{
            StatusCode = 400
            Body       = "Validate Inputs Failed"
        })
    }
if ($valid.AllValid){
    Set-Step -Name "Validate Inputs" -Status "Completed" -Ticket $Ticket
}
    else { 
        Set-Step -Name "Validate Inputs" -Message "Validate Inputs failed for fields $($valid.FailedFields)" -Status "Failed" -Ticket $Ticket
        return (New-Object -TypeName HttpResponseContext -Property @{
        StatusCode = 400
        Body       = "Validate Inputs Failed"
        })
    }

# 3) Create sub-tasks
Set-Step -Name "Create Jira Subtasks" -Status "Started" -Ticket $Ticket 
try {
    $jst = Add-JiraSubtasks -UserId $upn -Ticket $Ticket -Assignee $assignee -DueDate $dueDate -businessUnit $businessUnit
    if (-not $jst){
        throw [InvalidOperationException]::new("Add-JiraSubTasks did not return a successful result.")
    }
}
    catch {
        Set-Step -Name "Create Jira Subtasks" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
    }
if ($jst){
    Set-Step -Name "Create Jira Subtasks" -Message $jst.Message -Status $jst.Status -Ticket $Ticket
}
