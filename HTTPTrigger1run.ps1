<#
.SYNOPSIS
   Offboard an internal employee, contractor, or intern.
.DESCRIPTION
   Using details from offboarding ticket, the Entra account will set to expire on their last day at 5pm and be disabled. Change and log password
   Block Signin, remove/revoke MFA, sign out of all active MS sessions and convert the usermailbox into shared mailbox.
.EXAMPLE
   When triggered through the ticket the automation will send a web request to an Azure Function
#>
using namespace System.Net

param($Request, $TriggerMetadata)

$ErrorActionPreference = 'Stop'
$debugEnabled = $false
$FailRunOnAnyError = $false

$script:wxBearerToken = $null
$script:StepResults = New-Object System.Collections.ArrayList
$script:OneDriveResult = New-Object System.Collections.ArrayList
$script:MailboxResult = New-Object System.Collections.ArrayList


function Validate-Inputs {
    # Validate webhook inputs. Check for mandaitory values; check for minimum and maximum values. 
    param([hashtable]$Inputs)

    # --- Declarative validation rules ---
    $ValidationRules = @{
        Password       = @{ Min=1; Max=256; Mandatory=$true }
        dataExpiry     = @{ Min=9; Max= 10; Mandatory=$false} 
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

function Get-UserExists {
    # Verify Entra user. Checks every X seconds up to a maximum of Y attempts. 
    param(
        [Parameter(Mandatory)][string]$UserId,
        [int]$MaxAttempts = 5,
        [int]$SleepSeconds = 30
    )
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        Write-Log -Message "Checking for user account $UserId. Try #$i of #$MaxAttempts" -Level "Verbose" -Activity "Get-UserExists"
        try {
            $mguser = Get-MgUser -UserId $UserId -ErrorAction SilentlyContinue
        } catch { }
        if ($null -ne $mguser) {
            Write-Log -Message "User account $UserId found." -Level "Verbose" -Activity "Get-UserExists"
            return $true
        }
        Start-Sleep -Seconds $SleepSeconds
    }
    Write-Log -Message "User account not found after $($MaxAttempts) attempts" -level "Verbose" -Activity "Get-UserExists"
    return $false
}

function Disable-Account {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [int]$MaxAttempts = 5,
        [int]$SleepSeconds = 30    
    )

    # Disable the account
    try {
        Update-MgUser -UserId $UserId -AccountEnabled:$false  -ErrorAction Stop
    }
        catch {
            throw "Unable to disable account for $($UserId): $($_.Exception.Message)"
        }

    # Verify account is disabled
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        Write-Log -Message "Checking account $UserId is disabled. Try #$i of #$MaxAttempts" -Level "Verbose" -Activity "Disable Account"
        try {
            $mguser = Get-MgUser -UserId $UserId -Property UserPrincipalName, AccountEnabled -ErrorAction SilentlyContinue
            if ($mguser.AccountEnabled -eq $false) {
                Write-Log -Message "User $UserId AccountEnabled is $($mgUser.AccountEnabled)" -Level "Verbose" -Activity "Disable Account"
                return $true
            }
        } catch { }
        Start-Sleep -Seconds $SleepSeconds
    }
    Write-Log -Message "User account $($mgUser.UserPrincipalName) not disabled after $($MaxAttempts) attempts. User AccountEnabled is $($mgUser.AccountEnabled)" -level "Verbose" -Activity "Disable Account"
    return $false
}

function Remove-AuthenticationMethods {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter()][int]$maxRetries = 10,
        [Parameter()][int]$SleepSeconds = 30
    )
    $retries = 0
    try {
        $authMethods = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction Stop
    }
        catch {
            throw "Unable to retrieve Entra authentication methods $($_.Exception.Message)"
        }
    # Loop through all authentication methods
    # Some methods are expected to take multiple attempts due to behavior with certain methods are set as default
    # Password cannot be reset or removed so the expected resultant method count is 1
    while (($authMethods.count -gt 1) -and ($retries -lt $maxRetries )){
        foreach ($method in $authMethods){
            switch ($method.AdditionalProperties['@odata.type']) {
                '#microsoft.graph.fido2AuthenticationMethod' { 
                        Write-Log -Message 'Attempting to remove fido2AuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationFido2Method -UserId $userid -Fido2AuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.emailAuthenticationMethod' { 
                        Write-log -Message 'Attempting to remove emailAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationEmailMethod -UserId $userid -EmailAuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { 
                        Write-log -Message 'Attempting to remove microsoftAuthenticatorAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $userid -MicrosoftAuthenticatorAuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.phoneAuthenticationMethod' { 
                        Write-log -Message 'Attempting to remove phoneAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationPhoneMethod -UserId $userid -PhoneAuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.softwareOathAuthenticationMethod' { 
                        Write-log -Message 'Attempting to remove softwareOathAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationSoftwareOathMethod -UserId $userid -SoftwareOathAuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.temporaryAccessPassAuthenticationMethod' { 
                        Write-log -Message 'Attempting to remove temporaryAccessPassAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $userid -TemporaryAccessPassAuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 
                        Write-log -Message 'Attempting to remove windowsHelloForBusinessAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                        Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId $userid -WindowsHelloForBusinessAuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                '#microsoft.graph.passwordAuthenticationMethod' {
                        # Reset-MgUserAuthenticationMethodPassword currently unsupported with Managed Identities
                        #$password  = Reset-MgUserAuthenticationMethodPassword -UserId $userId -AuthenticationMethodId $method.Id -ErrorAction SilentlyContinue
                }
                <#     
                '#microsoft.graph.qrCodePinAuthenticationMethod' {
                    #Remove-MgBetaUserAuthenticationQrCodePinMethod -UserId $userId -ErrorAction SilentlyContinue
                    #Write-log -Message 'Attempting to remove qrCodePinAuthenticationMethod' -Level Verbose -Activity "Remove Authentication Methods"
                } 
                #>   
                Default {
                        Write-log -Message "Unknown or unsupported auth method type: $($method.AdditionalProperties['@odata.type'])"  -Level Verbose -Activity "Remove Authentication Methods"
                }
            }
        }	
        try {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $userId
        }
            catch {
                throw "Unable to retrieve Entra authentication methods $($_.Exception.Message)"
            }
        $retries++
        start-sleep -s $SleepSeconds
    }
    $remainingAuthMethods = $authMethods.AdditionalProperties['@odata.type'] | where {$_ -ne "#microsoft.graph.passwordAuthenticationMethod"}
    Write-log -Message "Removable authentication methods remaining: $($remainingAuthMethods.count). $($failedAuthMethods -join ",")" -Level Verbose -Activity "Remove Authentication Methods"
    
    if ($remainingAuthMethods){
        return [pscustomobject]@{ Status="Failed"; remainingAuthMethods=$remainingAuthMethods} 
    }
        else {
            return [pscustomobject]@{ Status="Completed"; remainingAuthMethods=$remainingAuthMethods} 
        }
}

function Revoke-RWAUserActiveSession {
    param([Parameter(Mandatory)][string]$UserId)
    #Revoke Active Signin session
    try {
        $revoke = Revoke-MgUserSignInSession -UserId $UserId -ErrorAction Stop
        Write-Log -level "Verbose" -Message "Revoked active signin sessions" -Activity "Revoke User Session"
        return $true
    }
        catch {
            throw
        }
}

function Set-WebexUserForwarding {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [string]$ForwardingUser
    )
    try {
        $mgUser = Get-MgUser -UserId $UserId -Property employeeType -ErrorAction Stop
    }
        catch {
            throw "Unable to retrieve Entra user for disabling Webex user: $($_.Exception.Message)"
        }
    if (-not $ForwardingUser){
        try {
            $userManager = get-mgusermanager -userid $UserId -ErrorAction Stop
            $mgManager = get-mguser -userid $Manager.id -ErrorAction Stop
        }
            catch {
                throw "No forwarding user; unable to retrieve Entra manager $($_.Exception.Message)"
            }
        $ForwardingUser = $mgManager.UserPrincipalName 
    }
    # Not a contractor or intern
    if (($mgUser.employeeType -eq "Contractor") -or ($mgUser.employeeType -eq "Intern")) { return [pscustomobject]@{ Status="Skipped"; Message="User is a $($mgUser.employeeType)" }}

    # Get Webex API access token and validate the response.
    try {
        $wxBearerToken = Get-WebexAccessToken
    }
        catch {
            throw "Webex token retrieval failed: $($_.Exception.Message)"
        }
    # Check if the Webex user already exists
    try {
        $wxUser = Get-WebExUser -Email $UserId -Token $wxBearerToken
    }
        catch {
            throw "Webex lookup failed: $($_.Exception.Message)"
        }
    if ($wxUser){
        # Disable the user immediately (instead of wating for SCIM)
        Write-Log -Message "Webex user found $($wxUser.items.emails), $($wxUser.items.id)" -Level "Verbose" -Activity "Webex Phone Forwarding"
        try {
            $wxDisable = Disable-WebexUser -webexuser $wxuser -Token $wxBearerToken
        }
            catch {
                throw "Failed to disable Webex user: $($_.Exception.Message)"
            }
        try {
            $wxUser = Get-WebExUser -Email $UserId -Token $wxBearerToken
        }
            catch {
                throw "Webex lookup failed: $($_.Exception.Message)"
            }
        if ($wxUser.items.loginEnabled -eq $false){
            write-log -Message "Webex user $UserId disabled" -level "Verbose" -Activity "Webex Phone Forwarding"
        }
            else {
                throw "Webex user disablement failed"
            }   
        try {
            $wxCallIntercept = Disable-WebexCallIntercept -webexuser $wxuser -Token $wxBearerToken
        }
            catch {
                throw "Failed to disable Call Intercept: $($_.Exception.Message)"
            }
        if ($wxCallIntercept -eq $true){
            Write-Log -Message "Webex call intercept disabled" -Level "Verbose" -Activity "Webex Phone Forwarding"
        }
            else {
                throw "Webex call intercept disablement failed"
            }
        try {
            $wxCallForwarding = Set-WebexCallForwarding -webexuser $wxUser -phoneForwardingUser $ForwardingUser -Token $wxBearerToken
        }   
            catch {
                throw "Failed to set call forwarding: $($_.Exception.Message)"
            }
        if ($wxCallForwarding -eq $true){
            Write-Log -Message "Webex call fowwarding set" -Level "Verbose" -Activity "Webex Phone Forwarding"
        }
            else {
                throw "Webex call forwarding enablement failed"
            }
        return [pscustomobject]@{ Status="Completed"; Message="Webex phone $($wxuser.items.phoneNumbers.value) forwarding to $ForwardingUser"; ForwardingUser=$ForwardingUser }
    }
        else {
            return [pscustomobject]@{ Status="Skipped"; Message="User was not found in Webex"}
        }
}

function Disable-WebexUser {
    # Set a user in webex to inactive
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, HelpMessage="Must pass the webex user object, not the username.")]
        [object]$webexuser,
        [Parameter(Mandatory)][string]$Token
    )
    try {    
        $uri = "https://webexapis.com/v1/people/$($webexuser.items.id)?callingData=true&showAllTypes=true&minResponse=true"
                                    
        $headers = @{
            "Authorization" = "$Token"
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"                         
        }
        $form = @{
            "loginEnabled" = "false"
            "displayName"  = $webexuser.items.displayName
            "extension" =  $webexuser.items.extension
            "firstName" = $webexuser.items.firstName
            "lastName" = $webexuser.items.lastName
            "locationId" = $webexuser.items.locationId
            "title" = $webexuser.items.title
            "emails" = $webexuser.items.emails
            "licenses" = $webexuser.items.licenses
            "addresses" = $webexuser.items.addresses
            "phoneNumbers" = $webexuser.items.phoneNumbers
        }
    
        $jsonbody = $form | ConvertTo-Json
        write-log -Message $uri -level "debug" -Activity "Webex User Disable"
        write-log -Message $jsonbody -level "debug" -Activity "Webex User Disable"
        #update the user
        $response = Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $jsonbody
    }
    catch {
        throw
    }
}

function Disable-WebExCallIntercept {
    # Disable Webex call intercept for a user
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, HelpMessage="Must pass the webex user object, not the username.")]
        [object]$webexuser,
        [Parameter(Mandatory)][string]$Token
    )
    try {    
        $uri = "https://webexapis.com/v1/people/$($webexuser.items.id)/features/intercept"
        $headers = @{
            "Authorization" = "$Token"
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"                        
        }
        $form = @{
            "enabled" = "false"
        }
        $jsonbody = $form | ConvertTo-Json
        write-log -Message $uri -level "debug" -Activity "Webex Call Intercept Disable"
        write-log -Message $jsonbody -level "debug" -Activity "Webex Call Intercept Disable"
        $response = Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $jsonbody
    }
        catch {
            throw
        }    
    try {
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
        #$response = $response | ConvertFrom-Json
        if ($response.enabled -eq $false){
            return $true
        }
            else {
                return $false
            }
    }
        catch {
           throw 
        }
}

function Set-WebexCallForwarding {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Must pass the webex user object, not the username.")]
        [object]$webexuser,
        [Parameter(Mandatory)][string]$phoneForwardingUser,
        [Parameter(Mandatory)][string]$Token
    )
    $phoneForwardingNumber = (Get-WebExUser -Email $phoneForwardingUser -Token $Token).items.phoneNumbers.value
    $phoneForwardingNumberE164 = Select-PhoneNumber $phoneForwardingNumber
    try {    
        $uri = "https://webexapis.com/v1/people/$($webexuser.items.id)/features/callForwarding"
        $headers = @{
            "Authorization" = "$Token"
            "Content-Type"  = "application/json"
            "Accept"        = "application/json"
                                
        }
        $form = @{
            "callForwarding" = @{
                "always" = @{ 
                    "enabled" = "true"
                    "destination" = $phoneForwardingNumberE164
                    "ringReminderEnabled" = "false"
                    "destinationVoicemailEnabled" = "false"
                }
            }
        }
        $jsonbody = $form | ConvertTo-Json
        #update the user
        $response = Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $jsonbody
    }
        catch {
            throw
        }
    try {
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
        if ($response.callForwarding.always.enabled -eq $true){
            return $true
        }
            else {
                return $false
            }
    }
        catch {
            throw
        }
}

function Select-PhoneNumber {
    # From Copilot, utilizes regex to find and select a 10 digit phone number and return the value in E164 format
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Text,
        # Output format. Default is E.164 (e.g., +16175593485).
        [ValidateSet('E164','Raw','Digits')]
        [string]$Format = 'E164'
    )

    # US/Canada 10-digit phone pattern with optional +1/1, flexible separators, and boundary checks
    # Supports: 617-559-3485, (617) 559-3485, 617.559.3485, 617 559 3485, 6175593485, +1 617 559 3485, etc.
    $pattern = '(?<!\d)(?:\+?1[\s\-.]?)?(?:\(?[2-9]\d{2}\)?[\s\-.]?)[2-9]\d{2}[\s\-.]?\d{4}(?!\d)'

    $m = [regex]::Match($Text, $pattern)
    if (-not $m.Success) { return $null }

    $raw = $m.Value

    switch ($Format) {
        'Raw'    { return $raw }
        'Digits' {
            $d = ($raw -replace '\D')
            if ($d.Length -eq 11 -and $d.StartsWith('1')) { $d = $d.Substring(1) }
            if ($d.Length -eq 10) { return $d } else { return $null }
        }
        'E164'   {
            $d = ($raw -replace '\D')
            if     ($d.Length -eq 10) { return '+1' + $d }
            elseif ($d.Length -eq 11 -and $d.StartsWith('1')) { return '+' + $d }
            else { return $null }  # strict: anything non-10/11 becomes null
        }
    }
}

function Set-UserCoreFields {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$LeaveDate
    )
    try {
        $mgUser = Get-MgUser -UserId $UserId -Property employeeType,CompanyName -ErrorAction Stop
    }
        catch {
            throw "Unable to retrieve Entra user for updating core fields: $($_.Exception.Message)"
        }
    if ($mgUser.employeeType -eq "Contractor"){
            $Company = $mgUser.CompanyName
    }
        else {
            $Company = "xRWA Wealth Partners"
        }
    try {
        $mg = Update-MgUser -UserId $UserId -CompanyName $Company -employeeLeaveDateTime $LeaveDate
    } 
        catch {
            Write-Log -Message "Core field update failed: $($_.Exception.Message)" -Level "Warning"
            throw "$($_.Exception.Message)"
        }  

    Write-Log -Message "Core fields updated for $UserId" -Level "Verbose" -Activity "Update Core Fields"
    return $true
}

function Set-CustomAttributes {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$Ticket,
        [Parameter(Mandatory)][string]$dataExpiry,
        [int]$MaxAttempts = 6,
        [int]$SleepSeconds = 30
    )

    $params = @{
        customSecurityAttributes = @{
            HR = @{
                "@odata.type" = "#Microsoft.DirectoryServices.CustomSecurityAttributeValue"
                OffboardingTicket = $Ticket
                DataExpiry = $dataExpiry
            }
        }
    }

    try {
        Update-MgUser -UserId $userId -BodyParameter $params -ErrorAction Stop
    }
        catch {
            throw "$($_.Exception.Message)"
        }

    
    for ($i = 1; $i -le $MaxAttempts; $i++){
        Write-Log -Message "Verifying custom security attributes set for user account $UserId. Try #$i of #$MaxAttempts" -Level "Verbose" -Activity "Set Ticket"
        try {
            $mgUser = Get-MgUser -UserId $userId -Property "customSecurityAttributes"
            $mgUserTicket = $mgUser.customSecurityAttributes.AdditionalProperties.HR.OffboardingTicket
            $mgUserDataExpiry = $mgUser.customSecurityAttributes.AdditionalProperties.HR.DataExpiry
            if (($Ticket -eq $mgUserTicket) -and ($dataExpiry -eq $mgUserDataExpiry)){
                return $true
            }
        }
            catch {    
                # On final attempt, make the exception message visable
                if ($i -eq $MaxAttempts) {
                    throw "Unable to verify custom security attributes after $($MaxAttempts) attempts: $($_.Exception.Message)"
                }
            }
        Start-Sleep -Seconds $SleepSeconds
    }
    if (($Ticket -ne $mgUserTicket) -or ($dataExpiry -ne $mgUserDataExpiry)){
        return $false
    }
}

function Remove-Groups {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [int]$MaxAttempts = 5,
        [int]$SleepSeconds = 30
    )

    $membershipsRemoved = [System.Collections.Generic.List[object]]::new()
    $membershipsFailed  = [System.Collections.Generic.List[object]]::new()
    $ownersRemoved      = [System.Collections.Generic.List[object]]::new()
    $ownersFailed       = [System.Collections.Generic.List[object]]::new()

    $graphProperties = @(
      'Id'
      'DisplayName'
      'Mail'
      'MailEnabled'
      'SecurityEnabled'
      'GroupTypes'
      'MembershipRule'
    )

    try {
        $mgUser = Get-MgUser -UserId $UserId -Property Id,UserPrincipalName,DisplayName -ErrorAction Stop
    }
    	catch {
        	throw "Failed to retrieve Entra user $($UserId): $($_.Exception.Message)"
    	}

    try {
        $mgManager = Get-MgUser -UserId (Get-MgUserManager -UserId $userId -ErrorAction Stop).id -ErrorAction Stop
    }
        catch {
                throw "Failed to retrieve Entra manager for $($userId). Group ownership cannot be reassigned safely. $($_.Exception.Message)"
            }
    
    try {
        $exchUser = Get-EXORecipient -Identity $userId
    }
        catch {
            throw "Failed to retrieve Exchange user $($UserId): $($_.Exception.Message)"
        }
    
    try {
        $exchManager = Get-EXORecipient -Identity $mgManager.UserPrincipalName
    }
        catch {
            throw "Failed to retrieve Exchange manager for $($UserId): $($_.Exception.Message)"
        }

    try {
        $graphMemberGroups = @(
            Get-MgUserMemberOfAsGroup -UserId $userId -All -Property $graphProperties -ErrorAction Stop
        ) | Where-Object { (($_.GroupTypes -contains 'Unified') -or ($_.SecurityEnabled -eq $true -and $_.MailEnabled -eq $false)) -and ($_.GroupTypes -notcontains 'DynamicMembership') -and (-not $_.MembershipRule)}
    }
        catch {
            throw "Failed to retrieve Entra groups for $($UserId): $($_.Exception.Message)"
        }
    
    try {
        $exchangeGroups = @( Get-MgUserMemberOfAsGroup -UserId $userId -All -Property $graphProperties -ErrorAction Stop) | Where-Object { ($_.GroupTypes -notcontains 'Unified') -and ($_.MailEnabled -eq $true)}
        $exchangeMemberGroups = foreach ($group in $exchangeGroups) {
            Get-DistributionGroup -Identity $group.Mail -RecipientTypeDetails MailUniversalSecurityGroup,MailUniversalDistributionGroup -ResultSize Unlimited -ErrorAction Stop
        }
    }
        catch {
            throw "Failed to retrieve Exchange groups for $($UserId): $($_.Exception.Message)"
        }

    foreach ($group in $graphMemberGroups){
        try {
            $owners = @(Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction Stop)

            # If the user is also an owner, replace with manager
            if ($owners.Id -contains $mgUser.Id) {
                # Unified groups need the manager to be added as member before adding as an owner
                if ($group.GroupTypes -contains 'Unified') {
                    $members = @(Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop)
                    if ($members.Id -notcontains $mgManager.Id) {
                        $newMember = New-MgGroupMemberByRef -GroupId $group.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($mgManager.Id)" } -ErrorAction Stop
                        Write-Log -Message "Manager $($MgManager.UserPrincipalName) added as member of group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                    }
                        else {
                            Write-Log -Message "Manager $($mgManager.UserPrincipalName) is already a member of group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                        }
                }
                # Add the manager as owner
                if ($owners.Id -notcontains $mgManager.Id) {
                    $newOwner = New-MgGroupOwnerByRef -GroupId $group.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgManager.Id)" } -ErrorAction Stop
                    Write-Log -Message "Manager $($mgManager.UserPrincipalName) added as owner of group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                }
                    else {
                        Write-Log -Message "Manager $($mgManager.UserPrincipalName) is already an owner of group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                    }
                # Remove user as owner
                $removeOwner = Remove-MgGroupOwnerByRef -GroupId $group.Id -DirectoryObjectId $mgUser.id -Confirm:$false -ErrorAction Stop
                
                Write-Log -Message "Ownership removed from group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                $ownersRemoved.Add([pscustomobject]@{
                    GroupId     = $group.Id
                    DisplayName = $group.DisplayName
                    ManagerId   = $mgManager.Id
                    Reason      = "Manager assigned as replacement owner"
                })
            }
        }
                catch {
                    Write-Log -Message "Ownership could not be reassigned or removed from group $($group.DisplayName) [$($group.Id)]: $($_.Exception.Message)" -Level "Verbose" -Activity "Remove Groups"
                    $ownersFailed.Add([pscustomobject]@{
                        GroupId     = $group.Id
                        DisplayName = $group.DisplayName
                        ManagerId   = $mgManager.Id
                        Error       = $_.Exception.Message
                    })
                }
        try {
        # Remove user as member            
            $removeMember = Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $mgUser.id -Confirm:$false -ErrorAction Stop
                
            Write-Log -Message "Graph membership removed from group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
            $membershipsRemoved.Add([pscustomobject]@{
                GroupId     = $group.Id
                DisplayName = $group.DisplayName
                Method      = "Graph"
            })
        }
            catch {
                Write-Log -Message "Membership could not be removed from group $($group.DisplayName) [$($group.Id)]: $($_.Exception.Message)" -Level "Verbose" -Activity "Remove Groups"

                $membershipsFailed.Add([pscustomobject]@{
                    GroupId     = $group.Id
                    DisplayName = $group.DisplayName
                    MailEnabled = $group.MailEnabled
                    GroupTypes  = $group.GroupTypes -join ","
                    Error       = $_.Exception.Message
                })
            }
    }
    
    foreach ($group in $exchangeMemberGroups) {
        # OWNER PROCESSING
        try {
            $resolvedOwners = foreach ($owner in $group.ManagedBy) { Get-ExoRecipient $owner -ErrorAction SilentlyContinue }
            $managerIsOwner = $false
            foreach ($owner in $resolvedOwners) {
                if ($owner.ExternalDirectoryObjectId -eq $exchManager.ExternalDirectoryObjectId) {
                    $managerIsOwner = $true
                    break
                }
            }
            if ($resolvedOwners.ExternalDirectoryObjectId -contains $exchUser.ExternalDirectoryObjectId) {
                $update = @{
                    Remove = $exchUser.Identity
                }

                if (-not $managerIsOwner) {
                    $update.Add = $exchManager.Identity
                    Write-Log -Message "Manager $($mgManager.UserPrincipalName) will be added as owner of group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                }
                    else {
                        Write-Log -Message "Manager $($mgManager.UserPrincipalName) is already an owner of group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                    }
                $newOwner = Set-DistributionGroup -Identity $group.Identity -ManagedBy $update -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
                
                Write-Log -Message "Ownership removed from group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
                $ownersRemoved.Add([pscustomobject]@{
                    GroupId     = $group.Id
                    DisplayName = $group.DisplayName
                    ManagerId   = $mgManager.Id
                    Reason      = "Manager assigned as replacement owner"
                })
            }
        }
        catch {
            Write-Log -Message "Ownership could not be reassigned or removed from group $($group.DisplayName) [$($group.Id)]: $($_.Exception.Message)" -Level "Verbose" -Activity "Remove Groups"
            $ownersFailed.Add([pscustomobject]@{
                GroupId     = $group.Id
                DisplayName = $group.DisplayName
                ManagerId   = $mgManager.UserPrincipalName
                Error       = $_.Exception.Message
            })
        }
        # MEMBER PROCESSING
        try {
            $removeMember = Remove-DistributionGroupMember -Identity $group.Identity -Member $exchUser.PrimarySmtpAddress -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
            
            Write-Log -Message "Membership removed from Exchange group $($group.DisplayName) [$($group.Id)]." -Level "Verbose" -Activity "Remove Groups"
            $membershipsRemoved.Add([pscustomobject]@{
                GroupId     = $group.Id
                DisplayName = $group.DisplayName
                Method      = "Exchange"
            })
        }
            catch {
                Write-Log -Message "Membership could not be removed from Exchange group $($group.DisplayName) [$($group.Id)]: $($_.Exception.Message)" -Level "Verbose" -Activity "Remove Groups"
                $membershipsFailed.Add([pscustomobject]@{
                    GroupId     = $group.Id
                    DisplayName = $group.DisplayName
                    MailEnabled = $group.MailEnabled
                    GroupTypes  = $group.GroupTypes -join ","
                    Error       = $_.Exception.Message
                })
            }
    }

    $remainingMemberships  = [System.Collections.Generic.List[object]]::new()
    $verificationErrors    = [System.Collections.Generic.List[object]]::new()
    $remainingOwnedGroups  = @()

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $remainingMemberships.Clear()
        $verificationErrors.Clear()

        foreach ($removed in $membershipsRemoved) {
            try {
                $stillMember = $false

                if ($removed.Method -eq "Graph") {
                    $stillMember = [bool](Get-MgGroupMember -GroupId $removed.GroupId -All -ErrorAction Stop | Where-Object { $_.Id -eq $mgUser.Id })
                }
                    elseif ($removed.Method -eq "Exchange") {
                        $stillMember = [bool](Get-DistributionGroupMember -Identity $removed.GroupId -ErrorAction Stop | Where-Object { $_.PrimarySmtpAddress -eq $exchUser.PrimarySmtpAddress })
                    }

                if ($stillMember) {
                    $remainingMemberships.Add($removed)
                }
            }
                catch {
                    Write-Log -Message "Verification check failed for group $($removed.DisplayName) [$($removed.GroupId)] on attempt $attempt of $VerificationAttempts`: $($_.Exception.Message)" -Level "Verbose" -Activity "Remove Groups"
                    # Treat an unverifiable group as still-remaining so it gets retried and, if it never
                    # clears, still shows up in the final report rather than silently passing.
                    $remainingMemberships.Add($removed)
                    $verificationErrors.Add([pscustomobject]@{
                        GroupId     = $removed.GroupId
                        DisplayName = $removed.DisplayName
                        Attempt     = $attempt
                        Error       = $_.Exception.Message
                    })
                }
        }

        if ($remainingMemberships.Count -eq 0) {
            Write-Log -Message "All group memberships confirmed removed after attempt $i of $MaxAttempts." -Level "Verbose" -Activity "Remove Groups"
            break
        }

        Write-Log -Message "$($remainingMemberships.Count) group membership(s) still showing on attempt $i of $MaxAttempts. Groups: $(($remainingMemberships.DisplayName) -join ', ')" -Level "Verbose" -Activity "Remove Groups"

        if ($i -lt $MaxAttempts) {
            Start-Sleep -Seconds $SleepSeconds
        }
    }

    if ($remainingMemberships.Count -gt 0) {
        Write-Log -Message "Final verification still shows $($remainingMemberships.Count) group membership(s) after $MaxAttempts attempt(s). Group ids: $(($remainingMemberships.GroupId) -join ', ')" -Level "Verbose" -Activity "Remove Groups"
    }

    if ( ($remainingMemberships.Count -eq 0) -and ($membershipsFailed.Count -eq 0) -and ($ownersFailed.Count -eq 0) ) {
        return [pscustomobject]@{
            Status                    = "Completed"
            Message                   = "All group memberships were removed and all group ownerships were reassigned to the user's manager."
            ManagerId                 = $mgManager.Id
            MembershipsRemovedCount   = $membershipsRemoved.Count
            OwnershipsRemovedCount    = $ownersRemoved.Count
            MembershipsRemainingCount = $remainingMemberships.Count
            OwnershipsRemainingCount  = @($remainingOwnedGroups).Count
            MembershipsRemoved        = $membershipsRemoved
            OwnershipsRemoved         = $ownersRemoved
        }
    }
        else {
            Write-Log -Message "Membership removal failures: $($membershipsFailed.Count)" -Activity "Remove Groups" -Level Verbose
            Write-Log -Message "Ownership reassignment/removal failures: $($ownersFailed.Count)" -Activity "Remove Groups" -Level Verbose
            Write-Log -Message "Memberships remaining after verification: $($remainingMemberships.Count)" -Activity "Remove Groups" -Level Verbose
            Write-Log -Message "Verification errors encountered: $($verificationErrors.Count)" -Activity "Remove Groups" -Level Verbose

            return [pscustomobject]@{
                Status                    = "Failed"
                Message                   = "$($membershipsFailed.Count) membership removals failed. $($ownersFailed.Count) ownership reassignments/removals failed. $($remainingMemberships.Count) memberships remain after $VerificationAttempts verification attempt(s)."
                ManagerId                 = $mgManager.Id
                MembershipsRemovedCount   = $membershipsRemoved.Count
                MembershipsFailedCount    = $membershipsFailed.Count
                OwnershipsRemovedCount    = $ownersRemoved.Count
                OwnershipsFailedCount     = $ownersFailed.Count
                MembershipsRemainingCount = $remainingMemberships.Count
                OwnershipsRemainingCount  = @($remainingOwnedGroups).Count
                MembershipsRemoved        = $membershipsRemoved
                MembershipsFailed         = $membershipsFailed
                OwnershipsRemoved         = $ownersRemoved
                OwnershipsFailed          = $ownersFailed
                MembershipsRemaining      = $remainingMemberships
                OwnershipsRemaining       = $remainingOwnedGroups
                VerificationErrors        = $verificationErrors
            }
        }
}

function Convert-UserMailbox {
    param(
        [parameter(mandatory)][string]$UserId
    )
    $ExchP1SkuId = "9aaf7827-d63c-4b61-89c3-182f06f82e5c"
    $ExchP2SkuId = "efb87545-963c-4e0d-99df-69c6916d9eb0"
    
    try {
        #$mgUser = Get-MgUser -UserId $UserId -Property UserPrincipalName
        $licenseDetails = Get-MgUserLicenseDetail -UserId $userId
    }
        catch {
            throw "Failed to retrieve Entra user mailbox license status $($_.Exception.Message)"
        }
    $exchangePlan = $licenseDetails.ServicePlans | where {($_.ServicePlanId -in @($ExchP1SkuId,$ExchP2SkuId)) -and ($_.ProvisioningStatus -eq "Success")}
    if ($exchangePlan){
        try {
            Set-Mailbox -identity $UserId -type Shared -ErrorAction Stop
            Set-Mailbox -identity $UserId -HiddenFromAddressListsEnabled $true -ErrorAction Stop
        }
            catch {
                throw "Failed to convert mailbox to shared and hide from the GAL: $($_.Exception.Message)"
            }
    }
        else {
            return [pscustomobject]@{ Status="Skipped"; Message="User is not licensed for an Exchange Online mailbox."}
        }
    return [pscustomobject]@{ Status="Completed"; Message="User Mailbox has been converted to a Shared Mailbox"}
}

function Grant-MailboxAccess {
    param(
        [parameter(mandatory)][string]$UserId,
        [parameter()][string[]]$additionalMembers,
        [int]$MaxAttempts = 6,
        [int]$SleepSeconds = 30
    )
    $Members = [System.Collections.Generic.List[string]]::new()
    $membersAdded = [System.Collections.Generic.List[string]]::new()
    $membersFailed = [System.Collections.Generic.List[string]]::new()

    for ($i = 1; $i -le $MaxAttempts; $i++){
        Write-Log -Message "Verifying mailbox has been converted to shared for $($UserId). Try #$i of #$MaxAttempts" -Level "Verbose" -Activity "Grant Mailbox Access"
        try {
            $mailbox = Get-Mailbox $UserId
            if ($mailbox.RecipientTypeDetails -eq "SharedMailbox"){
                break
            }
        }
            catch {    
                # On final attempt, make the exception message visable
                if ($i -eq $MaxAttempts) {
                    throw "Unable to verify mailbox type is Shared after $($MaxAttempts) attempts"
                }
            }
        Start-Sleep -Seconds $SleepSeconds
    }

    if ($mailbox.RecipientTypeDetails -eq "SharedMailbox"){
        Write-Log -Message "Mailbox has been converted to shared for $($UserId)." -Level "Verbose" -Activity "Grant Mailbox Access"
        try {
            $userManager = get-mgusermanager -userid $UserId
            $mgManager = get-mguser -userid $userManager.id
        }
            catch {
                throw "Unable to retrieve Entra manager $($_.Exception.Message)"
            }
        $Members.Add($mgManager.UserPrincipalName)
        if ($additionalMembers){
            foreach ($additionalMember in $additionalMembers){
                $Members.Add($additionalMember)
            }
        }
        foreach ($Member in $Members){
            try {
                    $mp = Add-MailboxPermission -Identity $UserId -User $Member -AccessRights FullAccess -InheritanceType All -AutoMapping $true
                    $membersAdded.Add($member)
                }
                catch {
                    write-log -Message "Unable to grant mailbox access to ${member}: $($_.Exception.Message)" -Level "Verbose" -Activity "Grant Mailbox Access"
                    $membersFailed.Add($member)
                }
        }      
        try {
            $newPerm = Get-MailboxPermission -Identity $UserId | Where-Object {-not $_.IsInherited -and $_.User -ne 'NT AUTHORITY\SELF'} | Select-Object -ExpandProperty User
        }
        catch {
            Write-Log -Message "Failed to retrieve mailbox permissions: $($_.Exception.Message)" -Level "verbose" -Activity "Grant Mailbox Access"
        }


        # Normalize both sides to strings for comparison
        $newPerm = $newPerm | ForEach-Object { $_.ToString().ToLower() }
        $expectedMembers = $Members | ForEach-Object { $_.ToLower() }

        $membersAdded = $newPerm | Where-Object { $_ -in $Members}
        $membersFailed = $expectedMembers | Where-Object { $_ -notin $newPerm }
        [void]$MailboxResult.Add($membersAdded)

        write-log -Message "$($MembersAdded.Count) users were reported to have been granted access. The users are: $MembersAdded" -Level "debug" -Activity "Grant Mailbox Access"
        write-log -Message "$($MembersFailed.Count) users were reported to have failed to be granted access. The users are: $MembersFailed" -Level "debug" -Activity "Grant Mailbox Access"

        if (-not $membersFailed) {
            return [pscustomobject]@{ Status="Completed"; Message="Shared Mailbox access has been granted for: $($membersAdded -join ', ')";MembersAdded=$MembersAdded }
        }
            else {
                Write-Log -Message "Failed to grant mailbox permissions for $($membersFailed -join ', ')" -Level "verbose" -Activity "Grant Mailbox Access"
                return [pscustomobject]@{ Status="Failed"; Message="$($membersFailed.Count) Users failed to be granted Shared Mailbox access." }
            }
    }
        else {
            return [pscustomobject]@{ Status="Skipped"; Message="Mailbox type is not SharedMailbox. Mailbox type is $($mailbox.RecipientTypeDetails)."}
        }
}

function Grant-OneDriveAccess {
    param(
        [parameter(mandatory)][string]$UserId,
        [parameter()][string[]]$additionalMembers
    )
    $Members = @()
    $membersAdded = [System.Collections.Generic.List[string]]::new()
    $membersFailed = [System.Collections.Generic.List[string]]::new()
    
    $uri = "/v1.0/users/$userId/drives?$select=webUrl"
    try {
        $response = Invoke-MgGraphRequest -Uri $uri -method GET
        write-log -Message "URI: $URI" -Activity "Grant OneDrive Access" -Level "Verbose"
        write-log -Message "Response: $($response.value.webUrl)" -Activity "Grant OneDrive Access" -Level "Verbose"
    }
        catch {
            throw "Failed retrieving OneDrive URL: $($_.Exception.Message)"
        }
    $userOneDriveWebURL = $response.value.webUrl | where {$_ -match "/Documents"}
    $userOneDriveURL = $userOneDriveWebURL.substring(0,$userOneDriveWebURL.indexof("/Documents"))
    try {  
        $PnPConnection = Connect-PnPOnline -URL $userOneDriveURL -ManagedIdentity -ReturnConnection
        write-log -Message "PNP Connection: $($PnPConnection.ConnectionMethod)" -Activity "Grant OneDrive Access" -Level "Verbose"
    }
        catch {
            throw "Failed connecting to OneDrive: $($_.Exception.Message)"
        }
    try {
        $userManager = get-mgusermanager -userid $UserId
        $mgManager = get-mguser -userid $userManager.id
    }
        catch {
            throw "Unable to retrieve Entra manager $($_.Exception.Message)"
        }
    $Members += $mgManager.UserPrincipalName
    if ($additionalMembers){
        foreach ($additionalMember in $additionalMembers){
            $Members += $additionalMember
        }
    }
    try {
        Add-PnPSiteCollectionAdmin -owners $Members
    }
        catch {
            throw "Failed granting permission to ${Members}: $($_.Exception.Message)"
        }
    try {
        $newPerm = Get-PnPSiteCollectionAdmin
        write-log -Message "Collection Administrators: $($CollectionOwners.Email)" -Activity "Assign OneDrive Access" -Level "Verbose"
    }
        catch {
            throw "Failed verifying collection administrators: $($_.Exception.Message)"
        }
    # Normalize both sides to strings for comparison
    $newPerm = $newPerm.Email | ForEach-Object { $_.ToString().ToLower() }
    $expectedMembers = $Members | ForEach-Object { $_.ToLower() }

    $membersFailed = $expectedMembers | Where-Object { $_ -notin $newPerm }
    $membersAdded = $expectedMembers | Where-Object { $_ -in $newPerm }
    [void]$OneDriveResult.Add($membersAdded)

    write-log -Message "$($MembersAdded.Count) users were reported to have been granted access. The users are: $MembersAdded" -Level "Verbose" -Activity "Grant OneDrive Access"
    write-log -Message "$($MembersFailed.Count) users were reported to have failed to be granted access. The users are: $MembersFailed" -Level "Verbose" -Activity "Grant OneDrive Access"

    if (-not $membersFailed) {
        return [pscustomobject]@{ Status="Completed"; Message="OneDrive access has been granted to $($membersAdded -join ', ')"; MembersAdded=$MembersAdded; UserOneDriveURL=$userOneDriveURL}
    }
        else {
            Write-Log -Message "Failed to grant OneDrive permissions for $($membersFailed -join ', ')" -Level "verbose" -Activity "Grant OneDrive Access" # Does this join method help output??
            return [pscustomobject]@{ Status="Failed"; Message="$($membersFailed.Count) Users failed to be granted OneDrive access." }
        }
}

function Set-M365License {
    # Remove M365 license, assign EXO P2 if needed
    param(
        [Parameter(Mandatory)][string]$UserId,
        [bool]$AssignExchP2 = $false,
        [string]$ExchP2SkuId = "efb87545-963c-4e0d-99df-69c6916d9eb0",
        [string]$E5SkuId = "06ebc4ee-1bb5-47dd-8120-11324bc54e06"
    )
    try {
        if ($AssignExchP2){
            Set-MgUserLicense -UserId $UserId -AddLicenses @(SkuId = $ExchP2SkuId) -RemoveLicenses @($E5SkuId) -ErrorAction Stop
            Write-Log -Message "M365 E5 removed successfully from $UserId" -Level "Verbose" -Activity "Set M365 License"
            Write-Log -Message "Exchange P2 added successfully to $UserId" -Level "Verbose" -Activity "Set M365 License"
        }
            else {
                Set-MgUserLicense -UserId $UserId -AddLicenses @() -RemoveLicenses @($E5SkuId) -ErrorAction Stop
                Write-Log -Message "M365 E5 removed successfully from $UserId" -Level "Verbose" -Activity "Set M365 License"
            }
        return $true
    }
        catch {
            Write-Log -Message "License assignment failed for $UserId : $($_.Exception.Message)" -Level "Error" -Activity "Set M365 License"
            throw
        }
}

function Send-OffboardingEmail {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string[]]$OneDriveMembers,
        [Parameter(Mandatory)][string]$OneDriveURL,
        [Parameter(Mandatory)][string[]]$MailboxMembers,
        [Parameter()][string]$PhoneForwarding
    )

    $MailboxMembersText = $MailboxMembers -join ', '
    $OneDriveMembersText = $OneDriveMembers -join ', '
    
    $MailboxURL = "https://outlook.office365.com/"+$($mailbox.PrimarySmtpAddress)
    $MessageContentMB = "The following people have been granted access to the mailbox of $($UserId): $($MailboxMembersText). They should see it appear in Outlook within the next day or they can access it via this URL: $MailboxURL" 
    $MessageContentOD = "The following people have been granted access to the OneDrive storage account of $($UserId): $($OneDriveMembersText). They may access it via this URL: $OneDriveURL"
    $MessageContent = $MessageContentMB + "<P>" + $MessageContentOD
    
    if ($PhoneForwarding){
        $MessageContentPF = "The phone of $($UserId) has been set to forward all calls to the Webex account of $($PhoneForwarding)."
        $MessageContent = $MessageContent + "<P>" + $($MessageContentPF)
    } 
    
    try {
        $userManager = get-mgusermanager -userid $UserId
        $mgManager = get-mguser -userid $userManager.id -property mail
    }
        catch {
            throw "Unable to retrieve Entra manager $($_.Exception.Message)"
        }
    try {             
        send-mail -To $mgManager.mail -Body $MessageContent -subject "Offboarding Notification"
        return $true
    }
        catch {
            Write-Log -Message "Send-OffboardingEmail for $UserId Failed: $($_.Exception.Message)" -Level "Error" -Activity "Send Offboarding Email"
            throw
        }
} 


Write-Log -Message "=== RWA IT Offboarding Runbook Started ===" -Level "information"

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
    Connect-RWAJiraPS
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
        Password=$password
        dataExpiry = $dataExpiry
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


# 6) Reset Password
Set-Step -Name "Reset Password" -Status "Started"

$newPassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$pwdProfile = @{
    password                         = $newPassword
    ForceChangePasswordNextSignIn    = $false     # or $true to force change
}

try { 
    $pw = Update-MgUser -UserId $upn -PasswordProfile $pwdProfile -errorAction Stop
    Set-Step -Name "Reset Password" -Message "New Password: $($Password)" -Status "Completed" -Ticket $Ticket
}
    catch {
        Set-Step -Name "Reset Password" -Message "Error: $($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        if ($FailRunOnAnyError) {
            Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
            return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Reset Password Failed"
            })  
        }
    }


# 4) Revoke Sign In Sessions
Set-Step -Name "Revoke User Session" -Status "Started"
   try {
        $rs = Revoke-RWAUserActiveSession -userId $upn
        if (-not $rs) {
            throw [InvalidOperationException]::new("Revoke-RWAUserActiveSession did not return a successful result.")
        }
    }
        catch {
            Set-Step -Name "Revoke User Session" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
            if ($FailRunOnAnyError) {
                Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
                return (New-Object -TypeName HttpResponseContext -Property @{
                    StatusCode = 400
                    Body       = "Revoke User Session Failed"
                })  
            }
        }
if ($rs){
    Set-Step -Name "Revoke User Session" -Message $rp.message -Status "Completed" -Ticket $Ticket
}

# 5) Remove Authentication Methods
Set-Step -Name "Remove Authentication Methods" -Status "Started"
try {
    $ram = Remove-AuthenticationMethods -userid $upn
}
    catch {
        Set-Step -Name "Remove Authentication Methods" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        if ($FailRunOnAnyError) { 
            Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
            return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Remove Authentication Methods"
            })  
        }
    }
if ($ram){
    switch ($ram.Status) {
        "Completed" { Set-Step -Name "Remove Authentication Methods" -Message "Remaining removable authentication methods: $($ram.remainingAuthMethods.Count)" -Status "Completed" -Ticket $Ticket }
        "Failed" { Set-Step -Name "Remove Authentication Methods" -Message "Remaining removable authentication methods: $($ram.remainingAuthMethods -join ",")" -Status "Failed" -Ticket $Ticket }
    }
}
    else {
        Set-Step -Name "Remove Authentication Methods" -Message "Unknown error" -Status "Failed" -Ticket $Ticket
    }

# 6) Disable Account
Set-Step -Name "Disable Account" -Status "Started"
try {
    $da = Disable-Account -userId $upn
    if (-not $da) {
        throw [InvalidOperationException]::new("Disable-Account did not return a successful result.")
    }
}
    catch {
        Set-Step -Name "Disable Account" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        if ($FailRunOnAnyError) {
            Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
            return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Disable Account Failed"
            })  
        }
    }
if ($da) {
    Set-Step -Name "Disable Account" -Status "Completed" -Ticket $Ticket
}

# 7) Webex Phone Forwarding
Set-Step -Name "Webex Phone Forwarding" -Status "Started"
try {
    $wx = Set-WebexUserForwarding -UserId $upn -ForwardingUser $phoneForwardingUser
    if (-not $wx) {
        throw [InvalidOperationException]::new("Set-WebexUserForwarding did not return a successful result.")
    }
}
    catch {
        Set-Step -Name "Webex Phone Forwarding" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        if ($FailRunOnAnyError) { 
            Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
            return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Webex Phone Forwarding Failed"
            })  
        }
    }
if ($wx){
    switch ($wx.Status) {
        "Completed" { Set-Step -Name "Webex Phone Forwarding" -Message $wx.Message -Status "Completed" -Ticket $Ticket }
        "Skipped" { Set-Step -Name "Webex Phone Forwarding" -Message $wx.Message -Status "Skipped" -Ticket $Ticket }
    }
}
    else {
        $wx = [pscustomobject]@{ Status = 'Failed' }
    }

# 8) Update Core Fields
Set-Step -Name "Update Core Fields" -Status "Started"
try {
    $userFields = Set-UserCoreFields -UserId $upn -LeaveDate $dueDate
    # Ensure every return that isn't $true is sent to catch. Then only a true result can complete the step.
    if (-not $userFields) {
        throw [InvalidOperationException]::new("Set-UserCoreFields did not return a successful result.")
    }
} 
    catch {
        Set-Step -Name "Update Core Fields" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        if ($FailRunOnAnyError) {
            Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
            return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Update Core Fields Failed"
            })    
        }
    }
if ($userFields){
    Set-Step -Name "Update Core Fields" -Status "Completed" -Ticket $Ticket
}

# 9) Set Custom Security Attributes
Set-Step -Name "Set Custom Attributes" -Status "Started"
# Use Custom Security Attributes to store information for future offboarding tasks   
try {
    
    $ca = Set-CustomAttributes -userid $upn -Ticket $Ticket -dataExpiry $dataExpiry
    if (-not $ca) {
        throw [InvalidOperationException]::new("Set-CustomAttributes did not return a successful result.")
    }
}
    catch {
        Set-Step -Name "Set Custom Attributes" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
        if ($FailRunOnAnyError) {
            Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
            return (New-Object -TypeName HttpResponseContext -Property @{
                StatusCode = 400
                Body       = "Set Ticket Failed"
            })    
        }
    }
if ($ca){
    Set-Step -Name "Set Custom Attributes" -Status "Completed" -Ticket $Ticket
}

# 10) Remove Groups
Set-Step -Name "Remove Groups" -Status "Started"
try {
    $Groups = Remove-Groups -UserId $upn
}
    catch{
        Set-Step -Name "Remove Groups" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
    }
if ($Groups){
    Set-Step -Name "Remove Groups" -Message $Groups.Message -Status $Groups.Status -Ticket $Ticket
}
    else {
        Set-Step -Name "Remove Groups" -Message "Unknown failure" -Status "Failed" -Ticket $Ticket
    }

# 11) Shared Mailbox
Set-Step -Name "Convert to Shared Mailbox" -Status "Started"
try {
    $mx = Convert-UserMailbox -userId $upn
}
    catch {
        Set-Step -Name "Convert to Shared Mailbox" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
    }
if ($mx){
    switch ($mx.Status) {
        "Completed" { Set-Step -Name "Convert to Shared Mailbox" -Message $mx.Message -Status "Completed" -Ticket $Ticket }
        "Skipped" { Set-Step -Name "Convert to Shared Mailbox" -Message $mx.Message -Status "Skipped" -Ticket $Ticket }
    }
}
    else {
        $mx = [pscustomobject]@{ Status = 'Failed' }
        Set-Step -Name "Convert to Shared Mailbox" -Message "Unknown failure" -Status "Failed" -Ticket $Ticket
    }

# 12) Grant Mailbox Access
Set-Step -Name "Grant Mailbox Access" -Status "Started"
try {
    $mbPerm = Grant-MailboxAccess -UserId $upn -additionalMembers $additionalMembers
}
    catch {
        Set-Step -Name "Grant Mailbox Access" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
    }
if ($mbPerm){
    switch ($mbPerm.Status) {
        "Completed" { Set-Step -Name "Grant Mailbox Access" -Message $mbPerm.Message -Status "Completed" -Ticket $Ticket }
        "Skipped" { Set-Step -Name "Grant Mailbox Access" -Message $mbPerm.Message -Status "Skipped" -Ticket $Ticket }
    }
}
    else {
        $mbPerm = [pscustomobject]@{ Status = 'Failed' }
        Set-Step -Name "Grant Mailbox Access" -Message "Unknown failure" -Status "Failed" -Ticket $Ticket
    }

# 12) Assign OneDrive Access
Set-Step -Name "Grant OneDrive Access" -Status "Started"
try {
    $odPerm = Grant-OneDriveAccess -UserId $upn -additionalMembers $additionalMembers
}
    catch {
        Set-Step -Name "Grant OneDrive Access" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
    }
if ($odPerm){
    switch ($odPerm.Status) {
        "Completed" { Set-Step -Name "Grant OneDrive Access" -Message $odPerm.Message -Status "Completed" -Ticket $Ticket }
        "Failed" { Set-Step -Name "Grant OneDrive Access" -Message $odPerm.Message -Status "Failed" -Ticket $Ticket }
    }
}
    else {
        $odPerm = [pscustomobject]@{ Status = 'Failed' }
        Set-Step -Name "Grant OneDrive Access" -Message "Unknown failure" -Status "Failed" -Ticket $Ticket
    }

# 13) Remove M365 License
Set-Step -Name "Set M365 License" -Status "Started"
if (($odPerm.Status -eq "Completed") -and ($mx.Status -eq "Completed")){
    try {
        $mL = Set-M365License -UserId $upn # Adjust for potential Exch P2 assignment
        if (-not $mL){
            throw [InvalidOperationException]::new("Set-M365License did not return a successful result.")
        }
    }
        catch {
            Set-Step -Name "Set M365 License" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
            if ($FailRunOnAnyError) { 
                Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
                return (New-Object -TypeName HttpResponseContext -Property @{
                    StatusCode = 400
                    Body       = "Set M365 License Failed"
                })  
            }
        }
    if ($mL){
        Set-Step -Name "Set M365 License" -Status "Completed" -Ticket $Ticket
    }
}
    else {
        $m365Message = "Skipped due to one or more previous steps: OneDrive Permissions $($odPerm.Status), Shared Mailbox $($mx.Status)"
        Set-Step -Name "Set M365 License" -Message $m365Message -Status "Skipped" -Ticket $Ticket 
    }

# 14) Send Offboarding Email
Set-Step -Name "Send Offboarding Email" -Status "Started"
if (($odPerm.Status -eq "Completed") -and ($mbPerm.Status -eq "Completed") -and ($wx.Status -ne "Failed")){
    try {
        $obe = Send-OffboardingEmail -UserId $upn -OneDriveMembers $odPerm.MembersAdded -OneDriveURL $odPerm.UserOneDriveURL -MailboxMembers $mbPerm.MembersAdded -PhoneForwarding $wx.ForwardingUser
    } 
        catch {
            Set-Step -Name "Send Offboarding Email" -Message "$($_.Exception.Message)" -Status "Failed" -Ticket $Ticket
            if ($FailRunOnAnyError) {
                Write-Log -Message "RWA IT Offboarding Runbook Aborted Early" -Level "information" -ticket $Ticket
                return (New-Object -TypeName HttpResponseContext -Property @{
                    StatusCode = 400
                    Body       = "Send New Hire Email Failed"
                }   )  
            }
        }
}
    else {
        $obeMessage = "Skipped due to one or more previous steps: OneDrive Permissions $($odPerm.Status), Mailbox Permissions $($mbPerm.Status), Webex Forwarding $($wx.Status)"
        Set-Step -Name "Send Offboarding Email" -Message $obeMessage -Status "Skipped" -Ticket $Ticket 
    }
if ($obe){
   Set-Step -Name "Send Offboarding Email" -Status "Completed" -Ticket $Ticket
}




# ---- FINAL CHECKLIST SUMMARY ----
Write-StepSummary
try {
    $md = Write-StepSummary -AsMarkdown
    write-log -Message $md -Level "Information" -Ticket $ticket
} catch {
    Write-Log -Message "Failed posting summary to Jira: $($_.Exception.Message)" -Level "Error"
}
Write-Log -Message "=== RWA IT Offboarding Runbook Finished ===" -Level "Information"
