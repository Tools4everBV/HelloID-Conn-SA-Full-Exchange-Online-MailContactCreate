# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Exchange Online in an unattended scripting scenario using a certificate.
# Follow the Microsoft Docs on how to set up the Azure App Registration: https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps
$AADOrganization = $AADExchangeOrganization
$AADAppID = $AADExchangeAppID
$AADCertificateThumbprint = $AADExchangeCertificateThumbprint # Certificate has to be locally installed

# Variables configured in form
$Alias = $form.alias
$ExternalEmailAddress = $form.ExternalEmailAddress
$initials = $form.Initials
$FirstName = $form.firstName
$LastName = $form.lastName
$Name = $form.displayName
$GroupsToAdd = $form.multiselectGroups
$HiddenFromAddressListsBoolean = $form.hideFromAddressLists

# PowerShell commands to import
$commands = @(
    "Get-User" # Always required
    , "Get-MailContact"
    , "New-MailContact"
    , "Set-MailContact"
    , "Add-DistributionGroupMember"
)

#region functions
function Remove-EmptyValuesFromHashtable {
    param(
        [parameter(Mandatory = $true)][Hashtable]$Hashtable
    )

    $newHashtable = @{}
    foreach ($Key in $Hashtable.Keys) {
        if (-not[String]::IsNullOrEmpty($Hashtable.$Key)) {
            $null = $newHashtable.Add($Key, $Hashtable.$Key)
        }
    }
    
    return $newHashtable
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}
#endregion functions

# Import module
$moduleName = "ExchangeOnlineManagement"

# If module is imported say that and do nothing
if (Get-Module | Where-Object { $_.Name -eq $ModuleName }) {
    Write-Verbose "Module $ModuleName is already imported."
}
else {
    # If module is not imported, but available on disk then import
    if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $ModuleName }) {
        $module = Import-Module $ModuleName -Cmdlet $commands
        Write-Verbose "Imported module $ModuleName"
    }
    else {
        # If the module is not imported, not available and not in the online gallery then abort
        throw "Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force"
    }
}

# Connect to Exchange
try {
    Write-Verbose "Connecting to Exchange Online"

    # Connect to Exchange Online in an unattended scripting scenario using a certificate thumbprint (certificate has to be locally installed).
    $exchangeSessionParams = @{
        Organization          = $AADOrganization
        AppID                 = $AADAppID
        CertificateThumbPrint = $AADCertificateThumbprint
        CommandName           = $commands
        ShowBanner            = $false
        ShowProgress          = $false
        TrackPerformance      = $false
        ErrorAction           = 'Stop'
    }

    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams
    
    Write-Information "Successfully connected to Exchange Online"
}
catch {
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObject = Resolve-HTTPError -Error $ex

        $verboseErrorMessage = $errorObject.ErrorMessage

        $auditErrorMessage = $errorObject.ErrorMessage
    }

    # If error message empty, fall back on $ex.Exception.Message
    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
        $verboseErrorMessage = $ex.Exception.Message
    }
    if ([String]::IsNullOrEmpty($auditErrorMessage)) {
        $auditErrorMessage = $ex.Exception.Message
    }

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
    throw "Error connecting to Exchange Online. Error Message: $auditErrorMessage"
}

try {
    # Check if Mail Contact already exists (should only occur on a retry of task)
    try {
        Write-Verbose "Querying Exchange Online mail contact with ExternalEmailAddress '$ExternalEmailAddress' OR Alias '$Alias' OR Name '$Name'"

        $mailContact = Get-MailContact -Filter "ExternalEmailAddress -eq '$ExternalEmailAddress' -or Alias -eq '$Alias' -or Name -eq '$Name'"

        Write-Information "Successfully queried Exchange Online mail contact with ExternalEmailAddress '$ExternalEmailAddress' OR Alias '$Alias' OR Name '$Name'. Result count: $($mailContact.GUID.Count)"
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex
    
            $verboseErrorMessage = $errorObject.ErrorMessage
    
            $auditErrorMessage = $errorObject.ErrorMessage
        }
    
        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }

        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        throw "Error creating mail contact with the following parameters: $($mailContactParams|ConvertTo-Json). Error Message: $auditErrorMessage"

        # Clean up error variables
        Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
        Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
    }

    if ($null -ne $mailContact.GUID) {
        Write-Warning "Found existing mail contact with ExternalEmailAddress '$ExternalEmailAddress' OR Alias '$Alias' OR Name '$Name'. Updating existing mail contact."
    }
    else {
        # Create Mail Contact
        try {
            Write-Verbose "Creating mail contact '$($Name)' with ExternalEmailAddress '$($ExternalEmailAddress)'"

            $mailContactParams = @{
                Name                 = $Name
                FirstName            = $FirstName
                Initials             = $Initials
                LastName             = $LastName
                Alias                = $Alias
        
                ExternalEmailAddress = $ExternalEmailAddress
            }
            $mailContactParams = Remove-EmptyValuesFromHashtable $mailContactParams

            $mailContact = New-MailContact @mailContactParams -ErrorAction Stop

            Write-Information "Successfully created mail contact with the following parameters: $($mailContactParams|ConvertTo-Json)"
            $Log = @{
                Action            = "CreateAccount" # optional. ENUM (undefined = default) 
                System            = "ExchangeOnline" # optional (free format text) 
                Message           = "Successfully created mail contact with the following parameters: $($mailContactParams|ConvertTo-Json)" # required (free format text) 
                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) 
                TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) 
            }
            #send result back
            Write-Information -Tags "Audit" -MessageData $log
        }
        catch {
            $ex = $PSItem
            if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObject = Resolve-HTTPError -Error $ex
        
                $verboseErrorMessage = $errorObject.ErrorMessage
        
                $auditErrorMessage = $errorObject.ErrorMessage
            }
        
            # If error message empty, fall back on $ex.Exception.Message
            if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                $verboseErrorMessage = $ex.Exception.Message
            }
            if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                $auditErrorMessage = $ex.Exception.Message
            }
    
            $Log = @{
                Action            = "CreateAccount" # optional. ENUM (undefined = default) 
                System            = "ExchangeOnline" # optional (free format text) 
                Message           = "Error creating mail contact with the following parameters: $($mailContactParams|ConvertTo-Json). Error Message: $auditErrorMessage" # required (free format text) 
                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                TargetDisplayName = $([string]$mailContactParams.Name) # optional (free format text) 
                TargetIdentifier  = $([string]$mailContactParams.ExternalEmailAddress) # optional (free format text) 
            }
            #send result back  
            Write-Information -Tags "Audit" -MessageData $log
    
            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
            throw "Error creating mail contact with the following parameters: $($mailContactParams|ConvertTo-Json). Error Message: $auditErrorMessage"
    
            # Clean up error variables
            Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
            Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
        }
    }

    # Optionally, update Mail Contact
    try {
        Write-Verbose "Updating mail contact '$($MailContact.Identity)'"

        $mailContactUpdateParams = @{
            Identity          = $MailContact.Guid
            # CustomAttribute15 = 'HelloID'
        }
    
        if ($HiddenFromAddressListsBoolean -eq 'true') {
            $mailContactUpdateParams.Add('HiddenFromAddressListsEnabled', $true)
        }
    
        $mailContactUpdateParams = Remove-EmptyValuesFromHashtable $mailContactUpdateParams

        $updatedMailContact = Set-MailContact @mailContactUpdateParams -ErrorAction Stop

        Write-Information "Successfully updated mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json)"
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ExchangeOnline" # optional (free format text) 
            Message           = "Successfully updated mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json)" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) 
            TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex
    
            $verboseErrorMessage = $errorObject.ErrorMessage
    
            $auditErrorMessage = $errorObject.ErrorMessage
        }
    
        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }

        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ExchangeOnline" # optional (free format text) 
            Message           = "Error updating mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json). Error Message: $auditErrorMessage" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $([string]$MailContact.Guid) # optional (free format text) 
            TargetIdentifier  = $([string]$MailContact.DisplayName) # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log

        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        throw "Error updating mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json). Error Message: $auditErrorMessage"

        # Clean up error variables
        Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
        Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
    }

    # Optionally, add Mail Contact to group(s)
    if ($null -ne $GroupsToAdd) {
        foreach ($groupToAdd in $GroupsToAdd) {
            try {
                Write-Verbose "Adding mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))'"

                $mailContactAddToGroupParams = @{
                    Identity                        = $groupToAdd.guid
                    Member                          = $MailContact.Guid
                    BypassSecurityGroupManagerCheck = $true
                    Confirm                         = $false
                }
            
                $mailContactAddToGroupParams = Remove-EmptyValuesFromHashtable $mailContactAddToGroupParams

                $mailContactAddedToGroup = Add-DistributionGroupMember @mailContactAddToGroupParams -ErrorAction Stop

                Write-Information "Successfully added mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))'"
                $Log = @{
                    Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                    System            = "ExchangeOnline" # optional (free format text) 
                    Message           = "Successfully added mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))'" # required (free format text) 
                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                    TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) 
                    TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) 
                }
                #send result back  
                Write-Information -Tags "Audit" -MessageData $log
            }
            catch {
                $ex = $PSItem
                if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                    $errorObject = Resolve-HTTPError -Error $ex
            
                    $verboseErrorMessage = $errorObject.ErrorMessage
            
                    $auditErrorMessage = $errorObject.ErrorMessage
                }
            
                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                if ($auditErrorMessage -like "*already a member of the group*") {
                    Write-Information "Successfully added mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))' (already a member)"
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = "Successfully added mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))' (already a member)" # required (free format text) 
                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) 
                        TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) 
                    }
                    #send result back  
                    Write-Information -Tags "Audit" -MessageData $log
                }
                else {
                    $Log = @{
                        Action            = "GrantMembership" # optional. ENUM (undefined = default) 
                        System            = "ExchangeOnline" # optional (free format text) 
                        Message           = "Error adding mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))'. Error Message: $auditErrorMessage" # required (free format text) 
                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
                        TargetDisplayName = $([string]$MailContact.Guid) # optional (free format text) 
                        TargetIdentifier  = $([string]$MailContact.DisplayName) # optional (free format text) 
                    }
                    #send result back  
                    Write-Information -Tags "Audit" -MessageData $log

                    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
                    Write-Error "Error adding mail contact '$($MailContact.Identity)' to group '$($groupToAdd.id) ($($groupToAdd.guid))'. Error Message: $auditErrorMessage" # Not a critical error
                }

                # Clean up error variables
                Remove-Variable 'verboseErrorMessage' -ErrorAction SilentlyContinue
                Remove-Variable 'auditErrorMessage' -ErrorAction SilentlyContinue
            }
        }
    }
}
finally {
    Write-Verbose "Disconnection from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop    
    Write-Information "Successfully disconnected from Exchange Online"
}