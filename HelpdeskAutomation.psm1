<#
.Synopsis
   Custom Function made for On/Offboarding
.DESCRIPTION
   Use to reduce the reduncy on calling/writing the same commands/function over and over again
.EXAMPLE
   Import-Module .\HelpDeskAutomation.psm1
#>

# Step Tracking (Success / Failed / Skipped)
$script:StepResults = New-Object System.Collections.ArrayList

function Log-Message {
   param ($level,$output,$ticket)
   if ($WebhookJSON){
      $issue = $WebhookJSON.key
   }
   if ($ticket){
      $issue = $ticket
   }
   switch ($level) {
      debug { Write-Output "$level, $output" }
      informational { Add-JiraIssueComment -Comment $output -Issue $issue -VisibleRole "Developers" }
      critical { Write-Output "Fatal error: $output"; exit }
   }  
}

function Write-Log { 
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Debug','Verbose','Information','Started','Completed','Skipped','Failed','Warning','Error')][string]$Level = 'Information',
        [string]$Activity,
        [string]$ticket
    )
    $InformationPreference = 'Continue'
    $VerbosePreference = 'Continue'   
    $DebugPreference = 'Continue'

    $prefix = ""
    if ($Activity) { $prefix += "[$Activity]" }

    switch ($Level) {
        'Debug'   { Write-Debug "$prefix $Message" }
        'Verbose'  { 
            $prefix = "[$level]"+$prefix
            Write-Information "$prefix $Message"
        }
        'Information'    { 
            Write-Information "$prefix $Message"
            if ($ticket){
                $prefix = "[$level]"+$prefix
                try {Add-JiraIssueComment -Comment "$prefix $Message" -Issue $ticket -VisibleRole "Developers" | Out-Null} catch { Write-Verbose "[$Level][JiraError] $($_.Exception.Message)"}
            }
        }
        'Started' { 
            Write-Information "$prefix $Message"
            if ($ticket){
                $prefix = "[$level]"+$prefix
                try {Add-JiraIssueComment -Comment "$prefix $Message" -Issue $ticket -VisibleRole "Developers" | Out-Null} catch { Write-Verbose "[$Level][JiraError] $($_.Exception.Message)"}
            }
        }
        'Completed' { 
            Write-Information "$prefix $Message"
            if ($ticket){
                $prefix = "[$level]"+$prefix
                try {Add-JiraIssueComment -Comment "$prefix $Message" -Issue $ticket -VisibleRole "Developers" | Out-Null} catch { Write-Verbose "[$Level][JiraError] $($_.Exception.Message)"}
            }
        }
        'Skipped' {
            Write-Warning "$prefix $Message"
            if ($ticket){
                $prefix = "[$level]"+$prefix
                try {Add-JiraIssueComment -Comment "$prefix $Message" -Issue $ticket -VisibleRole "Developers" | Out-Null} catch { Write-Verbose "[$Level][JiraError] $($_.Exception.Message)"}
            }
        }
        'Failed' {
            Write-Error "$prefix $Message"
            if ($ticket){
                $prefix = "[$level]"+$prefix
                try {Add-JiraIssueComment -Comment "$prefix $Message" -Issue $ticket -VisibleRole "Developers" | Out-Null} catch { Write-Verbose "[$Level][JiraError] $($_.Exception.Message)"}
            }
        }
        'Warning' { Write-Warning "$prefix $Message" }
        'Error'   { Write-Error   "$prefix $Message" }
    }
}

function get-offboardingtable {
   # Get storage account variables. The storage account holds the job table. 
   $storageaccount = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-storageaccount" -AsPlainText
   $resourcegroup = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-resourcegroup" -AsPlainText
   $storagetable = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-offboarding-table" -AsPlainText
   $sa = get-azstorageaccount -ResourceGroupName $resourcegroup -Name $storageaccount
   $Global:Table = get-azstoragetable -name $storagetable -context $sa.context   
}

function get-onboardingtable {
   # Get storage account variables. The storage account holds the job table. 
   $storageaccount = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-storageaccount" -AsPlainText
   $resourcegroup = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-resourcegroup" -AsPlainText
   $storagetable = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-onboarding-table" -AsPlainText
   $sa = get-azstorageaccount -ResourceGroupName $resourcegroup -Name $storageaccount
   $Global:Table = get-azstoragetable -name $storagetable -context $sa.context
}

function Connect-Graph {
   # Connect to Microsoft Graph
   try {
      $tenantid = Get-AzKeyVaultSecret -VaultName $keyvault -Name "tenantid" -AsPlainText
      $clientid = Get-AzKeyVaultSecret -VaultName $keyvault -Name "clientid-secret" -AsPlainText
      $CertificateName = Get-AzKeyVaultSecret -VaultName $keyvault -Name "certificate-name-secret" -AsPlainText
      $Certificate = Get-AzKeyVaultSecret -VaultName $keyvault -Name $CertificateName -AsPlainText
      $pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @([Convert]::FromBase64String($Certificate), "", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
      Connect-MgGraph -TenantId $tenantid -ClientId $clientid -Certificate $pfxCert | Out-Null
   }
      catch {
         $message = "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
         Write-Log -level "Error" -Message $message
         throw 
      }  
}

function Get-TableRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$TableName
    )

    $baseUri = "https://$StorageAccountName.table.core.windows.net/$TableName()"

    # Acquire Storage token and normalize to plain text
    try {
        $tokenRaw = Get-AzAccessToken -ResourceTypeName Storage
    }
        catch {
            Write-Log -Message "Error: Cannot retrieve access token for storage table $TableName in $StorageAccountName" -level "Error" -Activity "Get-TableRow"
            throw
        }

    if ($tokenRaw.Token -is [System.Security.SecureString]) {
        try {
            $tokenText = ConvertFrom-SecureString -SecureString $tokenRaw.Token -AsPlainText
        }
        catch {
            $tokenText = (New-Object System.Net.NetworkCredential("", $tokenRaw.Token)).Password
        }
    } else {
        $tokenText = [string]$tokenRaw.Token
    }



    # Set headers
    $headers = @{
        "Accept"       = "application/json;odata=nometadata"
        "x-ms-version" = "2020-08-04"
        "Authorization"= "$($tokenRaw.Type) $tokenText"
    }

    $allRows = New-Object System.Collections.Generic.List[object]
    $nextUri = $baseUri

    # Paginated results require retrieving a response until there is no longer a 'next' row. 
    do {
        $headers["x-ms-date"] = (Get-Date).ToUniversalTime().ToString("R")
        try {
            $resp = Invoke-WebRequest -Method GET -Uri $nextUri -Headers $headers -Verbose:$false -ProgressAction SilentlyContinue
           
        }
            catch {
                Write-Log -Message "Error: Cannot retrieve rows from storage table $TableName in $StorageAccountName" -level "Error" -Activity "Get-TableRow"
                throw
            }
        
        $json = $resp.Content | ConvertFrom-Json
        # Add the new values to the object collection
        if ($json.value) { $allRows.AddRange($json.value) }

        # Follow continuation tokens until none
        $npk = $resp.Headers.'x-ms-continuation-NextPartitionKey'
        $nrk = $resp.Headers.'x-ms-continuation-NextRowKey'
        if ($npk) { $nextUri = "$baseUri?NextPartitionKey=$npk&NextRowKey=$nrk" }
    } while ($npk)

    if ($allRows){
        return $allRows.ToArray()
    }
        else { 
            return $false
        }
}

function Add-TableRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$PartitionKey,
        [Parameter(Mandatory)][string]$RowKey,
        [Parameter()][hashtable]$Properties
    )

    # URLs
    $tableUrl  = "https://$StorageAccountName.table.core.windows.net/$TableName"  # POST here (insert)
    $entityUrl = "https://$StorageAccountName.table.core.windows.net/$TableName(PartitionKey='$([uri]::EscapeDataString($PartitionKey))',RowKey='$([uri]::EscapeDataString($RowKey))')"  # MERGE here


    # Acquire Storage token and normalize to plain text
    try {
        $tokenRaw = Get-AzAccessToken -ResourceTypeName Storage
    }
        catch {
            Write-Log -Message "Error: Cannot retrieve access token for storage table $TableName in $StorageAccountName" -level "Error" -Activity "Add-TableRow"
            throw
        }

    # Normalize token string
    if ($tokenRaw.Token -is [System.Security.SecureString]) {
        try {
            $tokenText = ConvertFrom-SecureString -SecureString $tokenRaw.Token -AsPlainText
        }
        catch {
            $tokenText = (New-Object System.Net.NetworkCredential("", $tokenRaw.Token)).Password
        }
    } else {
        $tokenText = [string]$tokenRaw.Token
    }

    #Write-Log -Message "Azure Table Access Token: $tokenText" -level "Debug" -Activity "Add-TableRow"

    $headers = @{
        "Accept"        = "application/json;odata=nometadata"
        "Content-Type"  = "application/json"
        "x-ms-version"  = "2020-08-04"
        "x-ms-date"     = (Get-Date).ToUniversalTime().ToString("R")
        "Authorization" = "$($tokenRaw.Type) $tokenText"
    }
  
    # MERGE headers require If-Match
    $mergeHeaders = $headers.Clone()
    $mergeHeaders["If-Match"] = "*"

    # Build entity body
    $entity = @{
        PartitionKey = $PartitionKey
        RowKey       = $RowKey
    }

    if ($Properties) {
        foreach ($k in $Properties.Keys) {
            $entity[$k] = $Properties[$k]
        }
    }

    $body = ($entity | ConvertTo-Json -Depth 10)

    try {
        # Expect 201 for insert
        $resp = Invoke-WebRequest -Method POST -Uri $tableUrl -Headers $headers -Body $body -Verbose:$false -UseBasicParsing
        #Write-Log -Message "Storage table response: $resp" -level "Debug" -Activity "Add-TableRow"
        return $true
    } 
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            # If insert failed because it exists, MERGE
            if ($statusCode -eq 409) {
                try {
                    # Expect 204 No Content
                    $resp2 = Invoke-WebRequest -Method MERGE -Uri $entityUrl -Headers $mergeHeaders -Body $body -ErrorAction Stop
                    #Write-Log -Message "Storage table response: $resp2" -level "Debug" -Activity "Add-TableRow"
                    return $true
                } catch {
                    throw "Merge failed for PK='$PartitionKey', RK='$RowKey'. $($_.Exception.Message)"
                }
            }
        throw "Insert failed with unexpected error $statusCode $($_.Exception.Message)"
    }
}

function Remove-TableRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][string]$PartitionKey,
        [Parameter(Mandatory)][string]$RowKey
    )

    $entityUrl = "https://$StorageAccountName.table.core.windows.net/$TableName(PartitionKey='$([uri]::EscapeDataString($PartitionKey))',RowKey='$([uri]::EscapeDataString($RowKey))')"

    # Acquire Storage token and normalize to plain text
    try {
        $tokenRaw = Get-AzAccessToken -ResourceTypeName Storage
    }
        catch {
            Write-Log -Message "Error: Cannot retrieve access token for storage table $TableName in $StorageAccountName" -level "Error" -Activity "Remove-TableRow"
            throw
        }

    # Normalize token string
    if ($tokenRaw.Token -is [System.Security.SecureString]) {
        try {
            $tokenText = ConvertFrom-SecureString -SecureString $tokenRaw.Token -AsPlainText
        }
        catch {
            $tokenText = (New-Object System.Net.NetworkCredential("", $tokenRaw.Token)).Password
        }
    } else {
        $tokenText = [string]$tokenRaw.Token
    }

    #Write-Log -Message "Azure Table Access Token: $tokenText" -level "Debug" -Activity "Remove-TableRow"

    # Headers
    $headers = @{
        "Accept"        = "application/json;odata=nometadata"
        "x-ms-version"  = "2020-08-04"
        "x-ms-date"     = (Get-Date).ToUniversalTime().ToString("R")
        "Authorization" = "$($tokenRaw.Type) $tokenText"
        "If-Match"      = "*"
    }

    try {
        # Expect 204 No Content
        $resp = Invoke-WebRequest -Method DELETE -Uri $entityUrl -Headers $headers -ErrorAction Stop
        return $true
    } catch {
        $status = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
        }
        if ($status -eq 404) { return $false } # not found – report or ignore as needed
        throw "Delete failed for PK='$PartitionKey', RK='$RowKey' (status $status): $($_.Exception.Message)"
    }
}

function Set-Step {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][ValidateSet('Started','Completed','Failed','Skipped')][string]$Status = 'Started',
        [string]$Message,
        [string]$Ticket
    )

    switch ($Status) {
        'Started' {
            # Start a fresh entry
            $entry = [pscustomobject]@{
                Name      = $Name
                Status    = 'Started'
                Message   = $Message
                StartedAt = Get-Date
                EndedAt   = $null
                DurationS = $null
            }
            [void]$script:StepResults.Add($entry)
            Write-Log -Message 'Step Started' -Activity $Name -Level 'Started'
        }

        default {
            # Find the last instance of this step
            $step = $script:StepResults | Where-Object { $_.Name -eq $Name } | Select-Object -Last 1

            if ($null -eq $step) {
                write-log -Message "No step named '$Name' was found to mark as '$Status'." -activity "Set-Step" -level 'Warning'
            }
            $step.Status    = $Status
            $step.Message   = switch ($Status) {
                    'Completed' { 'Step completed successfully' }
                    'Failed'  { 'Step Failed' }
                    'Skipped' { 'Step Skipped' }
                    default   { '' }
            }

            $step.EndedAt   = Get-Date
            $step.DurationS = [Math]::Round( ($step.EndedAt - $step.StartedAt).TotalSeconds, 1 )
            
            if (-not $Message){$Message = $step.Message}
            Write-Log -Message $Message -Activity $Name -Level $status -Ticket $Ticket
        }
    }
}

function Write-StepSummary {
    param([switch]$AsMarkdown)

    $total   = $script:StepResults.Count
    $Completed = ($script:StepResults | Where-Object Status -eq "Completed").Count
    $fail    = ($script:StepResults | Where-Object Status -eq "Failed").Count
    $skip    = ($script:StepResults | Where-Object Status -eq "Skipped").Count

    if ($AsMarkdown) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("**Step Summary**")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("- **Total:** $total")
        [void]$sb.AppendLine("- **Completed:** $Completed")
        [void]$sb.AppendLine("- **Failures:** $fail")
        [void]$sb.AppendLine("- **Skipped:** $skip")
        [void]$sb.AppendLine("")
        foreach ($s in $script:StepResults) {
            $icon = switch ($s.Status) {
                "Completed" { "✅" }
                "Failed"  { "❌" }
                "Skipped" { "⏭️" }
                default   { "❓" }
            }
            [void]$sb.AppendLine("$icon **$($s.Name)** — $($s.Message) *(Duration: $($s.DurationS)s)*")
        }
        return $sb.ToString()
    }

    Write-Log -Message "===== STEP SUMMARY =====" -level "Information"
    foreach ($s in $script:StepResults) {
        $row = switch ($s.Status) {
            "Completed" { "[OK]" }
            "Failed"  { "[X]" }
            "Skipped" { "[>>]" }
            default   { "[?]" }
        }
        Write-Log -Message "$row $($s.Name) — $($s.Message)" -level "Information"
    }
    Write-Log -Message "========================" -level "Information"
}

Function Get-RandomPassword {
   #define parameters
   param([Parameter(ValueFromPipeline = $false)][ValidateRange(1, 256)][int]$PasswordLength = 10)
   try { 
      #ASCII Character set for Password
      $CharacterSet = @{
         Lowercase   = (97..122) | Get-Random -Count 10 | % { [char]$_ }
         Uppercase   = (65..90)  | Get-Random -Count 10 | % { [char]$_ }
         Numeric     = (48..57)  | Get-Random -Count 10 | % { [char]$_ }
         SpecialChar = (33..47) + (58..64) + (91..96) + (123..126) | Get-Random -Count 10 | % { [char]$_ }
      }

      #Frame Random Password from given character set
      $StringSet = $CharacterSet.Uppercase + $CharacterSet.Lowercase + $CharacterSet.Numeric + $CharacterSet.SpecialChar

      $password = -join (Get-Random -Count $PasswordLength -InputObject $StringSet)
      return $password
    }
    catch {
        write-log -Message "$($_.Exception.Message)" -level "Error" -Activity "Get-RandomPassword"
        throw
    }
}

function Connect-JiraPS {
   Import-Module JiraPS
   if (($env:jira_Server) -and ($env:jira_svcaccount_Username) -and ($env:jira_svcaccount_APIToken)){
       write-log -Message "Jira environment variables found" -Level "Verbose" -Activity "Connect-JiraPS"
       $jiraURI = $env:jira_Server
       $jiraUsername = $env:jira_svcaccount_Username
       $jiraAPIToken = $env:jira_svcaccount_APIToken
   }
   if ($keyvault){
       write-log -Message "Jira Keyvault variable found" -Level "Verbose" -Activity "Connect-JiraPS"
       $jiraURI = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jiracfg-server-secret" -AsPlainText
       $jiraUsername = Get-AzKeyVaultSecret -VaultName $keyvault -Name "username-secret" -AsPlainText
       $jiraAPIToken = Get-AzKeyVaultSecret -VaultName $keyvault -Name "apitoken-secret" -AsPlainText
   }
   try {
      Set-JiraConfigServer $jiraURI -ErrorAction Stop | Out-Null
      #Calling the connection needed
      $password = ConvertTo-SecureString -String $jiraAPIToken -AsPlainText -Force
      $jiraautomationcred = new-object -TypeName System.Management.Automation.PSCredential -ArgumentList $jiraUsername, $password
      New-JiraSession -Credential $jiraautomationcred -ErrorAction Stop | Out-Null
      # Not used
      #$pair = "${username}:${jiraautomationsecret}"
      #$user = [System.Text.Encoding]::UTF8.GetBytes($pair)
   }
    catch {
        write-log -level "Error" -output "Unable to authenticate to Jira: $($_.Exception.Message)"
    }    
}

function get-offboardingjobs {
    try {
       # Retrieve table from storage account. 
        $global:rows = Get-AzTableRow -table $table.CloudTable
        #write-output $rows
    }
    catch {
        $outputmessage = "Unable to get table rows"
        write-output $outputmessage
    }
}

function get-onboardingjobs {
    try {
       # Retrieve table from storage account. 
        $global:rows = Get-AzTableRow -table $table.CloudTable
        #write-output $rows
    }
    catch {
        $outputmessage = "Unable to get table rows"
        write-output $outputmessage
    }
}

function send-mail {
   param ($To,$Body,$Subject)
   write-log -level "verbose" -Activity "Send-Mail" -Message "To $To"
   write-log -level "verbose" -Activity "Send-Mail" -Message "Subject $Subject"
   write-log -level "verbose" -Activity "Send-Mail" -Message  "Body $Body"

   # Get the from address. The application must have an exchange online authorization policy to the distribution list used. 
   if ($env:mail_From){
       $from = $env:mail_From
    }
        else {
            try {
                $from = Get-AzKeyVaultSecret -VaultName $keyvault -Name "mail-from" -AsPlainText
            }
                catch { 
                    throw
                }
        }
   
   # This header defines the style of the email content. 
   $htmlHeader = "
      <br>
      <style>
      table {
         font-family: Trebuchet MS, Arial, Helvetica, sans-serif;
         border-collapse: collapse;
         white-space: nowrap;
      }
      th {
         text-align: left;
         background-color: #5c99d6;
         color: white;
         white-space: nowrap;
         padding-right: 5px;
         padding-left: 5px;
         border: 1px solid black;
         border-collapse: collapse;
      }
      td {
         padding-right: 5px;
         padding-left: 5px;
         white-space: nowrap;
         border: 1px solid black;
         border-collapse: collapse;
      }
      </style>
      "
   # Combine the header and body content into an HTML object package
   $EmailBody = ConvertTo-Html -head $htmlHeader -precontent $Body

   # Craft and send the mail message
   $toArray = $to.Split(",")
   $ToRecipients = @()
   foreach ($item in $toArray) {
      $ToRecipients += @{ 
         emailAddress = @{
            address = $item
         }
      }
   }
   $Message = @{
      subject = $Subject;
      toRecipients = $ToRecipients;
      body = @{
         contentType = "HTML";
         content = "$EmailBody"
      }
   }
   try {
      Send-MgUserMail -UserId $from -Message $Message
   }
      catch {
         throw
      }
      finally {
         write-log -level "debug" -Activity "Send-Mail" -Message "Mail message: $($message | ConvertTo-Json -Depth 5)"
      }
}

function get-phonetable {
   # Get storage account variables. The storage account holds the job table. 
   $storageaccount = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-storageaccount" -AsPlainText
   $resourcegroup = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-resourcegroup" -AsPlainText
   $storagetable = Get-AzKeyVaultSecret -VaultName $keyvault -Name "jira-phonenumber-table" -AsPlainText
   $sa = get-azstorageaccount -ResourceGroupName $resourcegroup -Name $storageaccount
   $Global:WebExTable = get-azstoragetable -name $storagetable -context $sa.context   
}

function get-phonenumberrow {
   try {
      # Retrieve table from storage account. 
      $global:WebExRows = Get-AzTableRow -table $WebExTable.CloudTable
      #write-output $rows
   }
   catch {
      $outputmessage = "Unable to get phone table rows"
      write-output $outputmessage
      Write-Warning $Error[0]
   }
}

function Get-WebexAccessToken {
    param (
        [string]$keyVault
    )
    # Get Access Token for Webex
    if (($env:webex_clientId) -and ($env:webex_clientSecret) -and ($env:webex_tokenRequestURI)){
       write-log -Message "Webex environment variables found" -Level "Verbose" -Activity "Get-WebexAccessToken"
       $clientId = $env:webex_clientId
       $clientSecret = $env:webex_clientSecret
       $tokenUri = $env:webex_tokenRequestURI
   }
   if ($keyvault){
        write-log -Message "Webex keyvault variable found" -Level "Verbose" -Activity "Get-WebexAccessToken"
        $clientId     = Get-AzKeyVaultSecret -VaultName $keyVault -Name "WebEx-ClientID" -AsPlainText
        $clientSecret = Get-AzKeyVaultSecret -VaultName $keyVault -Name "WebEx-ClientSecret" -AsPlainText
        $tokenUri     = Get-AzKeyVaultSecret -VaultName $keyVault -Name "WebEx-Token" -AsPlainText
    }
    try {
        $body         = @{ clientId = $clientId; clientSecret = $clientSecret } | ConvertTo-Json

        $resp = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ErrorAction Stop -Verbose:$false
        $wxBearerToken = "Bearer $($resp.accessToken)"

        Write-Log -Message "Webex API access token retrieved successfully." -Level "Verbose" -Activity "Assign Webex Phone"
        #Write-Log -Message "Webex Bearer Token: $wxBearerToken" -Level "Debug" -Activity "Assign Webex Phone"
        return $wxBearerToken
    }
    catch {
        throw 
    }
}

function Get-WebexUser {
    # Get a user from Webex
    param(
        [Parameter(Mandatory)][string]$Email,
        [Parameter(Mandatory)][string]$Token
    )
    try {
        $headers = @{ Authorization = $Token; Accept = "application/json"; "Content-Type" = "application/json" }
        $uri = "https://webexapis.com/v1/people?email=$Email"
        $wxuser = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop -Verbose:$false
        return $wxuser
    }
    catch {
        throw
    }
}

function Add-BusinessDays {
    # Generated with Gemini 3.6 Flash, Modified with GPT-5
    param (
        [DateTime]$StartDate = (Get-Date),
        [int]$DaysToAdd,
        [DateTime[]]$Holidays = @()
    )

    if ($DaysToAdd -eq 0) {
        return $StartDate
    }

    $currentDate = $StartDate
    $daysMoved = 0
    $direction = if ($DaysToAdd -gt 0) { 1 } else { -1 }

    while ($daysMoved -lt [Math]::Abs($DaysToAdd)) {

        # Move ford or backward one day
        $currentDate = $currentDate.AddDays($direction)

        $isWeekend = $currentDate.DayOfWeek -in @('Saturday', 'Sunday')
        $isHoliday = $currentDate.Date -in $Holidays

        if (-not $isWeekend -and -not $isHoliday) {
            $daysMoved++
        }
    }

    return $currentDate
}

function Get-JiraAuthHeader {
    param (
        [Parameter(Mandatory)][string]$JiraUser,
        [Parameter(Mandatory)][string]$ApiToken
    )
    $authString = "$($JiraUser):$($ApiToken)"
    $base64Auth = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes($authString)
    )
    $headers = @{
        Authorization = "Basic $base64Auth"
        Accept        = "application/json"
    }
    return $headers
}

Export-ModuleMember -Function Log-Message
Export-ModuleMember -Function Get-RandomPassword
Export-ModuleMember -Function Connect-JiraPS
Export-ModuleMember -Function get-offboardingjobs
Export-ModuleMember -Function get-onboardingjobs
Export-ModuleMember -Function send-mail
Export-ModuleMember -Function get-offboardingtable
Export-ModuleMember -Function get-onboardingtable
Export-ModuleMember -Function Connect-Graph
Export-ModuleMember -Function get-phonetable
Export-ModuleMember -Function get-phonenumberrow
Export-ModuleMember -Function Get-TableRow
Export-ModuleMember -Function Add-TableRow
Export-ModuleMember -Function Remove-TableRow
Export-ModuleMember -Function Set-Step
Export-ModuleMember -Function Write-StepSummary
Export-ModuleMember -Function Write-Log
Export-ModuleMember -Function Get-WebexAccessToken
Export-ModuleMember -Function Get-WebexUser
Export-ModuleMember -Function Add-BusinessDays
Export-ModuleMember -Function Get-JiraAuthHeader
Export-ModuleMember -Variable StepResults
