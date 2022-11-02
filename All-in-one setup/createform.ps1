# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#HelloID variables
#Note: when running this script inside HelloID; portalUrl and API credentials are provided automatically (generate and save API credentials first in your admin panel!)
$portalUrl = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
$delegatedFormAccessGroupNames = @("") #Only unique names are supported. Groups must exist!
$delegatedFormCategories = @("") #Only unique names are supported. Categories will be created if not exists
$script:debugLogging = $false #Default value: $false. If $true, the HelloID resource GUIDs will be shown in the logging
$script:duplicateForm = $false #Default value: $false. If $true, the HelloID resource names will be changed to import a duplicate Form
$script:duplicateFormSuffix = "_tmp" #the suffix will be added to all HelloID resource names to generate a duplicate form with different resource names

#The following HelloID Global variables are used by this form. No existing HelloID global variables will be overriden only new ones are created.
#NOTE: You can also update the HelloID Global variable values afterwards in the HelloID Admin Portal: https://<CUSTOMER>.helloid.com/admin/variablelibrary
$globalHelloIDVariables = [System.Collections.Generic.List[object]]@();

#Global variable #1 >> AADExchangeAppID
$tmpName = @'
AADExchangeAppID
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #2 >> AADExchangeOrganization
$tmpName = @'
AADExchangeOrganization
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});

#Global variable #3 >> AADExchangeCertificateThumbprint
$tmpName = @'
AADExchangeCertificateThumbprint
'@ 
$tmpValue = @'
'@ 
$globalHelloIDVariables.Add([PSCustomObject]@{name = $tmpName; value = $tmpValue; secret = "False"});


#make sure write-information logging is visual
$InformationPreference = "continue"

# Check for prefilled API Authorization header
if (-not [string]::IsNullOrEmpty($portalApiBasic)) {
    $script:headers = @{"authorization" = $portalApiBasic}
    Write-Information "Using prefilled API credentials"
} else {
    # Create authorization headers with HelloID API key
    $pair = "$apiKey" + ":" + "$apiSecret"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $key = "Basic $base64"
    $script:headers = @{"authorization" = $Key}
    Write-Information "Using manual API credentials"
}

# Check for prefilled PortalBaseURL
if (-not [string]::IsNullOrEmpty($portalBaseUrl)) {
    $script:PortalBaseUrl = $portalBaseUrl
    Write-Information "Using prefilled PortalURL: $script:PortalBaseUrl"
} else {
    $script:PortalBaseUrl = $portalUrl
    Write-Information "Using manual PortalURL: $script:PortalBaseUrl"
}

# Define specific endpoint URI
$script:PortalBaseUrl = $script:PortalBaseUrl.trim("/") + "/"  

# Make sure to reveive an empty array using PowerShell Core
function ConvertFrom-Json-WithEmptyArray([string]$jsonString) {
    # Running in PowerShell Core?
    if($IsCoreCLR -eq $true){
        $r = [Object[]]($jsonString | ConvertFrom-Json -NoEnumerate)
        return ,$r  # Force return value to be an array using a comma
    } else {
        $r = [Object[]]($jsonString | ConvertFrom-Json)
        return ,$r  # Force return value to be an array using a comma
    }
}

function Invoke-HelloIDGlobalVariable {
    param(
        [parameter(Mandatory)][String]$Name,
        [parameter(Mandatory)][String][AllowEmptyString()]$Value,
        [parameter(Mandatory)][String]$Secret
    )

    $Name = $Name + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl + "api/v1/automation/variables/named/$Name")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
    
        if ([string]::IsNullOrEmpty($response.automationVariableGuid)) {
            #Create Variable
            $body = @{
                name     = $Name;
                value    = $Value;
                secret   = $Secret;
                ItemType = 0;
            }    
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl + "api/v1/automation/variable")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $variableGuid = $response.automationVariableGuid

            Write-Information "Variable '$Name' created$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        } else {
            $variableGuid = $response.automationVariableGuid
            Write-Warning "Variable '$Name' already exists$(if ($script:debugLogging -eq $true) { ": " + $variableGuid })"
        }
    } catch {
        Write-Error "Variable '$Name', message: $_"
    }
}

function Invoke-HelloIDAutomationTask {
    param(
        [parameter(Mandatory)][String]$TaskName,
        [parameter(Mandatory)][String]$UseTemplate,
        [parameter(Mandatory)][String]$AutomationContainer,
        [parameter(Mandatory)][String][AllowEmptyString()]$Variables,
        [parameter(Mandatory)][String]$PowershellScript,
        [parameter()][String][AllowEmptyString()]$ObjectGuid,
        [parameter()][String][AllowEmptyString()]$ForceCreateTask,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $TaskName = $TaskName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        $uri = ($script:PortalBaseUrl +"api/v1/automationtasks?search=$TaskName&container=$AutomationContainer")
        $responseRaw = (Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false) 
        $response = $responseRaw | Where-Object -filter {$_.name -eq $TaskName}
    
        if([string]::IsNullOrEmpty($response.automationTaskGuid) -or $ForceCreateTask -eq $true) {
            #Create Task

            $body = @{
                name                = $TaskName;
                useTemplate         = $UseTemplate;
                powerShellScript    = $PowershellScript;
                automationContainer = $AutomationContainer;
                objectGuid          = $ObjectGuid;
                variables           = (ConvertFrom-Json-WithEmptyArray($Variables));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/automationtasks/powershell")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
            $taskGuid = $response.automationTaskGuid

            Write-Information "Powershell task '$TaskName' created$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        } else {
            #Get TaskGUID
            $taskGuid = $response.automationTaskGuid
            Write-Warning "Powershell task '$TaskName' already exists$(if ($script:debugLogging -eq $true) { ": " + $taskGuid })"
        }
    } catch {
        Write-Error "Powershell task '$TaskName', message: $_"
    }

    $returnObject.Value = $taskGuid
}

function Invoke-HelloIDDatasource {
    param(
        [parameter(Mandatory)][String]$DatasourceName,
        [parameter(Mandatory)][String]$DatasourceType,
        [parameter(Mandatory)][String][AllowEmptyString()]$DatasourceModel,
        [parameter()][String][AllowEmptyString()]$DatasourceStaticValue,
        [parameter()][String][AllowEmptyString()]$DatasourcePsScript,        
        [parameter()][String][AllowEmptyString()]$DatasourceInput,
        [parameter()][String][AllowEmptyString()]$AutomationTaskGuid,
        [parameter(Mandatory)][Ref]$returnObject
    )

    $DatasourceName = $DatasourceName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    $datasourceTypeName = switch($DatasourceType) { 
        "1" { "Native data source"; break} 
        "2" { "Static data source"; break} 
        "3" { "Task data source"; break} 
        "4" { "Powershell data source"; break}
    }
    
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/datasource/named/$DatasourceName")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
      
        if([string]::IsNullOrEmpty($response.dataSourceGUID)) {
            #Create DataSource
            $body = @{
                name               = $DatasourceName;
                type               = $DatasourceType;
                model              = (ConvertFrom-Json-WithEmptyArray($DatasourceModel));
                automationTaskGUID = $AutomationTaskGuid;
                value              = (ConvertFrom-Json-WithEmptyArray($DatasourceStaticValue));
                script             = $DatasourcePsScript;
                input              = (ConvertFrom-Json-WithEmptyArray($DatasourceInput));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
      
            $uri = ($script:PortalBaseUrl +"api/v1/datasource")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
              
            $datasourceGuid = $response.dataSourceGUID
            Write-Information "$datasourceTypeName '$DatasourceName' created$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        } else {
            #Get DatasourceGUID
            $datasourceGuid = $response.dataSourceGUID
            Write-Warning "$datasourceTypeName '$DatasourceName' already exists$(if ($script:debugLogging -eq $true) { ": " + $datasourceGuid })"
        }
    } catch {
      Write-Error "$datasourceTypeName '$DatasourceName', message: $_"
    }

    $returnObject.Value = $datasourceGuid
}

function Invoke-HelloIDDynamicForm {
    param(
        [parameter(Mandatory)][String]$FormName,
        [parameter(Mandatory)][String]$FormSchema,
        [parameter(Mandatory)][Ref]$returnObject
    )
    
    $FormName = $FormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/forms/$FormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if(([string]::IsNullOrEmpty($response.dynamicFormGUID)) -or ($response.isUpdated -eq $true)) {
            #Create Dynamic form
            $body = @{
                Name       = $FormName;
                FormSchema = (ConvertFrom-Json-WithEmptyArray($FormSchema));
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/forms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $formGuid = $response.dynamicFormGUID
            Write-Information "Dynamic form '$formName' created$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        } else {
            $formGuid = $response.dynamicFormGUID
            Write-Warning "Dynamic form '$FormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $formGuid })"
        }
    } catch {
        Write-Error "Dynamic form '$FormName', message: $_"
    }

    $returnObject.Value = $formGuid
}


function Invoke-HelloIDDelegatedForm {
    param(
        [parameter(Mandatory)][String]$DelegatedFormName,
        [parameter(Mandatory)][String]$DynamicFormGuid,
        [parameter()][Array][AllowEmptyString()]$AccessGroups,
        [parameter()][String][AllowEmptyString()]$Categories,
        [parameter(Mandatory)][String]$UseFaIcon,
        [parameter()][String][AllowEmptyString()]$FaIcon,
        [parameter()][String][AllowEmptyString()]$task,
        [parameter(Mandatory)][Ref]$returnObject
    )
    $delegatedFormCreated = $false
    $DelegatedFormName = $DelegatedFormName + $(if ($script:duplicateForm -eq $true) { $script:duplicateFormSuffix })

    try {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$DelegatedFormName")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        } catch {
            $response = $null
        }
    
        if([string]::IsNullOrEmpty($response.delegatedFormGUID)) {
            #Create DelegatedForm
            $body = @{
                name            = $DelegatedFormName;
                dynamicFormGUID = $DynamicFormGuid;
                isEnabled       = "True";
                useFaIcon       = $UseFaIcon;
                faIcon          = $FaIcon;
                task            = ConvertFrom-Json -inputObject $task;
            }
            if(-not[String]::IsNullOrEmpty($AccessGroups)) { 
                $body += @{
                    accessGroups    = (ConvertFrom-Json-WithEmptyArray($AccessGroups));
                }
            }
            $body = ConvertTo-Json -InputObject $body -Depth 100
    
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
    
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Information "Delegated form '$DelegatedFormName' created$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
            $delegatedFormCreated = $true

            $bodyCategories = $Categories
            $uri = ($script:PortalBaseUrl +"api/v1/delegatedforms/$delegatedFormGuid/categories")
            $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $bodyCategories
            Write-Information "Delegated form '$DelegatedFormName' updated with categories"
        } else {
            #Get delegatedFormGUID
            $delegatedFormGuid = $response.delegatedFormGUID
            Write-Warning "Delegated form '$DelegatedFormName' already exists$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormGuid })"
        }
    } catch {
        Write-Error "Delegated form '$DelegatedFormName', message: $_"
    }

    $returnObject.value.guid = $delegatedFormGuid
    $returnObject.value.created = $delegatedFormCreated
}


<# Begin: HelloID Global Variables #>
foreach ($item in $globalHelloIDVariables) {
	Invoke-HelloIDGlobalVariable -Name $item.name -Value $item.value -Secret $item.secret 
}
<# End: HelloID Global Variables #>


<# Begin: HelloID Data sources #>
<# Begin: DataSource "Exchange-Online-group-generate-table" #>
$tmpPsScript = @'
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

# Variables provided from form

# PowerShell commands to import
$commands = @(
    "Get-User" # Always required
    , "Get-Group"
)

#region functions
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
    Write-Verbose "Querying Exchange Online groups"
    
    $groups = Get-Group -Identity * -ResultSize Unlimited

    $resultCount = $groups.GUID.Count

    Write-Information "Successfully queried Exchange Online groups. Result count: $resultCount"

    # Return info message if mailaddress is available or already in use
    if ($resultCount -gt 0) {
        foreach ($group in $groups) {
            $returnObject = @{
                guid        = "$($group.guid)"
                name        = "$($group.displayName)"
                id          = "$($group.id)"
                description = "$($group.description)"
                groupType   = "$($group.GroupType)"
            }
            Write-Output $returnObject
        }
    }
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
    throw "Error searching for Exchange Online groups. Error Message: $auditErrorMessage"
}
finally {
    Write-Verbose "Disconnection from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop    
    Write-Information "Successfully disconnected from Exchange Online"
}
'@ 
$tmpModel = @'
[{"key":"description","type":0},{"key":"name","type":0},{"key":"groupType","type":0},{"key":"id","type":0},{"key":"guid","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_3 = [PSCustomObject]@{} 
$dataSourceGuid_3_Name = @'
Exchange-Online-group-generate-table
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_3_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_3) 
<# End: DataSource "Exchange-Online-group-generate-table" #>

<# Begin: DataSource "Exchange-Online-group-emailaddresses-uniqueness-check" #>
$tmpPsScript = @'
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

# Variables provided from form
$emailAddress = $datasource.emailaddress

# PowerShell commands to import
$commands = @(
    "Get-User" # Always required
    , "Get-Mailbox"
)

#region functions
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
    if ([String]::IsNullOrEmpty($emailAddress) -eq $true) {
        Write-Error "No emailAddress provided"
    }
    else { 
        Write-Verbose "Querying Exchange Online mailboxes with email address '$emailAddress'"
        
        $mailboxes = Get-Mailbox -Filter "EmailAddresses -eq '$emailAddress'"

        $resultCount = $mailboxes.GUID.Count

        Write-Information "Successfully queried Exchange Online mailboxes with email address '$emailAddress'. Result count: $resultCount"

        # Return true/false - true if none found (means mailaddress is available)
        if($resultCount -eq 0){
            $result = $true
        }else{
            $result = $false
        }

        $returnObject = @{Result=$result}
        Write-Output $returnObject
    }
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
    throw "Error searching for Exchange Online mailboxes with email address '$emailAddress'. Error Message: $auditErrorMessage"
}
finally {
    Write-Verbose "Disconnection from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop    
    Write-Information "Successfully disconnected from Exchange Online"
}
'@ 
$tmpModel = @'
[{"key":"Result","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"emailaddress","type":0,"options":1}]
'@ 
$dataSourceGuid_1 = [PSCustomObject]@{} 
$dataSourceGuid_1_Name = @'
Exchange-Online-group-emailaddresses-uniqueness-check
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_1_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_1) 
<# End: DataSource "Exchange-Online-group-emailaddresses-uniqueness-check" #>

<# Begin: DataSource "Exchange-Online-Contact-create-check-names" #>
$tmpPsScript = @'
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

# Variables provided from form
$emailAddress = $datasource.emailaddress

# PowerShell commands to import
$commands = @(
    "Get-User" # Always required
    , "Get-Mailbox"
)

#region functions
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
    if ([String]::IsNullOrEmpty($emailAddress) -eq $true) {
        Write-Error "No emailAddress provided"
    }
    else { 
        Write-Verbose "Querying Exchange Online mailboxes with email address '$emailAddress'"
        
        $mailboxes = Get-Mailbox -Filter "EmailAddresses -eq '$emailAddress'"

        $resultCount = $mailboxes.GUID.Count

        Write-Information "Successfully queried Exchange Online mailboxes with email address '$emailAddress'. Result count: $resultCount"

        # Return info message if mailaddress is available or already in use
        if($resultCount -eq 0){
            $result = "Email address $emailAddress is free to use"
        }else{
            $result = "Email address $emailAddress is already in use by another mailbox: $($mailboxes.DisplayName) ($($mailboxes.PrimarySmtpAddress))"
        }

        $returnObject = @{Result=$result}
        Write-Output $returnObject
    }
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
    throw "Error searching for Exchange Online mailboxes with email address '$emailAddress'. Error Message: $auditErrorMessage"
}
finally {
    Write-Verbose "Disconnection from Exchange Online"
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop    
    Write-Information "Successfully disconnected from Exchange Online"
}
'@ 
$tmpModel = @'
[{"key":"Result","type":0}]
'@ 
$tmpInput = @'
[{"description":null,"translateDescription":false,"inputFieldType":1,"key":"EmailAddress","type":0,"options":1}]
'@ 
$dataSourceGuid_2 = [PSCustomObject]@{} 
$dataSourceGuid_2_Name = @'
Exchange-Online-Contact-create-check-names
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_2_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_2) 
<# End: DataSource "Exchange-Online-Contact-create-check-names" #>

<# Begin: DataSource "test" #>
$tmpPsScript = @'
# script
Write-Output @{"test" = "test"}
'@ 
$tmpModel = @'
[{"key":"test","type":0}]
'@ 
$tmpInput = @'
[]
'@ 
$dataSourceGuid_0 = [PSCustomObject]@{} 
$dataSourceGuid_0_Name = @'
test
'@ 
Invoke-HelloIDDatasource -DatasourceName $dataSourceGuid_0_Name -DatasourceType "4" -DatasourceInput $tmpInput -DatasourcePsScript $tmpPsScript -DatasourceModel $tmpModel -returnObject ([Ref]$dataSourceGuid_0) 
<# End: DataSource "test" #>
<# End: HelloID Data sources #>

<# Begin: Dynamic Form "Exchange Online - Contact - Create" #>
$tmpSchema = @"
[{"label":"Details","fields":[{"key":"externalEmailAddress","templateOptions":{"label":"External Email Address","placeholder":"j.doe@gmail.com","required":true,"useDataSource":false,"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_0","input":{"propertyInputs":[]}},"displayField":"test"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"emailUniqueBool","templateOptions":{"label":"Emailaddress available?","useSwitch":true,"checkboxLabel":"Yes","useDataSource":true,"mustBeTrue":true,"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_1","input":{"propertyInputs":[{"propertyName":"emailaddress","otherFieldValue":{"otherFieldKey":"externalEmailAddress"}}]}},"displayField":"Result"},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"emailUniqueInfo","templateOptions":{"label":"Info","rows":3,"useDataSource":true,"dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_2","input":{"propertyInputs":[{"propertyName":"EmailAddress","otherFieldValue":{"otherFieldKey":"externalEmailAddress"}}]}},"displayField":"Result","placeholder":"Loading..."},"hideExpression":"!model[\"externalEmailAddress\"]","className":"textarea-resize-vert","type":"textarea","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"displayName","templateOptions":{"label":"Display name","placeholder":"John Doe","required":true,"minLength":2},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"alias","templateOptions":{"label":"Alias","placeholder":"johndoe","required":true,"minLength":2,"pattern":"^[a-zA-Z0-9_.!#$%\u0026\u0027*+-\\/=?^_`{|}~]*$"},"validation":{"messages":{"pattern":"Valid values are: Strings formed with characters from A to Z (uppercase or lowercase), digits from 0 to 9, !, #, $, %, \u0026, \u0027, *, +, -, /, =, ?, ^, _, `, {, |, } or ~"}},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"firstName","templateOptions":{"label":"First name"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"initials","templateOptions":{"label":"Initials"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"lastName","templateOptions":{"label":"Last name"},"type":"input","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false},{"key":"hideFromAddressLists","templateOptions":{"label":"Hide from Address Lists","useSwitch":true,"checkboxLabel":"Hide from Address Lists"},"type":"boolean","summaryVisibility":"Show","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]},{"label":"Groups","fields":[{"key":"multiselectGroups","templateOptions":{"label":"Exchange Groups","useObjects":false,"useFilter":true,"options":["Option 1","Option 2","Option 3"],"useDataSource":true,"valueField":"id","textField":"name","dataSourceConfig":{"dataSourceGuid":"$dataSourceGuid_3","input":{"propertyInputs":[]}}},"type":"multiselect","summaryVisibility":"Show","textOrLabel":"text","requiresTemplateOptions":true,"requiresKey":true,"requiresDataSource":false}]}]
"@ 

$dynamicFormGuid = [PSCustomObject]@{} 
$dynamicFormName = @'
Exchange Online - Contact - Create
'@ 
Invoke-HelloIDDynamicForm -FormName $dynamicFormName -FormSchema $tmpSchema  -returnObject ([Ref]$dynamicFormGuid) 
<# END: Dynamic Form #>

<# Begin: Delegated Form Access Groups and Categories #>
$delegatedFormAccessGroupGuids = @()
if(-not[String]::IsNullOrEmpty($delegatedFormAccessGroupNames)){
    foreach($group in $delegatedFormAccessGroupNames) {
        try {
            $uri = ($script:PortalBaseUrl +"api/v1/groups/$group")
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
            $delegatedFormAccessGroupGuid = $response.groupGuid
            $delegatedFormAccessGroupGuids += $delegatedFormAccessGroupGuid
            
            Write-Information "HelloID (access)group '$group' successfully found$(if ($script:debugLogging -eq $true) { ": " + $delegatedFormAccessGroupGuid })"
        } catch {
            Write-Error "HelloID (access)group '$group', message: $_"
        }
    }
    if($null -ne $delegatedFormAccessGroupGuids){
        $delegatedFormAccessGroupGuids = ($delegatedFormAccessGroupGuids | Select-Object -Unique | ConvertTo-Json -Depth 100 -Compress)
    }
}

$delegatedFormCategoryGuids = @()
foreach($category in $delegatedFormCategories) {
    try {
        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories/$category")
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false
        $response = $response | Where-Object {$_.name.en -eq $category}
        
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid
        
        Write-Information "HelloID Delegated Form category '$category' successfully found$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    } catch {
        Write-Warning "HelloID Delegated Form category '$category' not found"
        $body = @{
            name = @{"en" = $category};
        }
        $body = ConvertTo-Json -InputObject $body -Depth 100

        $uri = ($script:PortalBaseUrl +"api/v1/delegatedformcategories")
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $script:headers -ContentType "application/json" -Verbose:$false -Body $body
        $tmpGuid = $response.delegatedFormCategoryGuid
        $delegatedFormCategoryGuids += $tmpGuid

        Write-Information "HelloID Delegated Form category '$category' successfully created$(if ($script:debugLogging -eq $true) { ": " + $tmpGuid })"
    }
}
$delegatedFormCategoryGuids = (ConvertTo-Json -InputObject $delegatedFormCategoryGuids -Depth 100 -Compress)
<# End: Delegated Form Access Groups and Categories #>

<# Begin: Delegated Form #>
$delegatedFormRef = [PSCustomObject]@{guid = $null; created = $null} 
$delegatedFormName = @'
Exchange Online - Contact - Create
'@
$tmpTask = @'
{"name":"Exchange Online - Contact - Create","script":"# Set TLS to accept TLS, TLS 1.1 and TLS 1.2\r\n[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12\r\n\r\n$VerbosePreference = \"SilentlyContinue\"\r\n$InformationPreference = \"Continue\"\r\n$WarningPreference = \"Continue\"\r\n\r\n# Used to connect to Exchange Online in an unattended scripting scenario using a certificate.\r\n# Follow the Microsoft Docs on how to set up the Azure App Registration: https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps\r\n$AADOrganization = $AADExchangeOrganization\r\n$AADAppID = $AADExchangeAppID\r\n$AADCertificateThumbprint = $AADExchangeCertificateThumbprint # Certificate has to be locally installed\r\n\r\n# Variables configured in form\r\n$Alias = $form.alias\r\n$ExternalEmailAddress = $form.ExternalEmailAddress\r\n$initials = $form.Initials\r\n$FirstName = $form.firstName\r\n$LastName = $form.lastName\r\n$Name = $form.displayName\r\n$GroupsToAdd = $form.multiselectGroups\r\n$HiddenFromAddressListsBoolean = $form.hideFromAddressLists\r\n\r\n# PowerShell commands to import\r\n$commands = @(\r\n    \"Get-User\" # Always required\r\n    , \"Get-MailContact\"\r\n    , \"New-MailContact\"\r\n    , \"Set-MailContact\"\r\n    , \"Add-DistributionGroupMember\"\r\n)\r\n\r\n#region functions\r\nfunction Remove-EmptyValuesFromHashtable {\r\n    param(\r\n        [parameter(Mandatory = $true)][Hashtable]$Hashtable\r\n    )\r\n\r\n    $newHashtable = @{}\r\n    foreach ($Key in $Hashtable.Keys) {\r\n        if (-not[String]::IsNullOrEmpty($Hashtable.$Key)) {\r\n            $null = $newHashtable.Add($Key, $Hashtable.$Key)\r\n        }\r\n    }\r\n    \r\n    return $newHashtable\r\n}\r\n\r\nfunction Resolve-HTTPError {\r\n    [CmdletBinding()]\r\n    param (\r\n        [Parameter(Mandatory,\r\n            ValueFromPipeline\r\n        )]\r\n        [object]$ErrorObject\r\n    )\r\n    process {\r\n        $httpErrorObj = [PSCustomObject]@{\r\n            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId\r\n            MyCommand             = $ErrorObject.InvocationInfo.MyCommand\r\n            RequestUri            = $ErrorObject.TargetObject.RequestUri\r\n            ScriptStackTrace      = $ErrorObject.ScriptStackTrace\r\n            ErrorMessage          = \u0027\u0027\r\n        }\r\n        if ($ErrorObject.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) {\r\n            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message\r\n        }\r\n        elseif ($ErrorObject.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027) {\r\n            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()\r\n        }\r\n        Write-Output $httpErrorObj\r\n    }\r\n}\r\n#endregion functions\r\n\r\n# Import module\r\n$moduleName = \"ExchangeOnlineManagement\"\r\n\r\n# If module is imported say that and do nothing\r\nif (Get-Module | Where-Object { $_.Name -eq $ModuleName }) {\r\n    Write-Verbose \"Module $ModuleName is already imported.\"\r\n}\r\nelse {\r\n    # If module is not imported, but available on disk then import\r\n    if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $ModuleName }) {\r\n        $module = Import-Module $ModuleName -Cmdlet $commands\r\n        Write-Verbose \"Imported module $ModuleName\"\r\n    }\r\n    else {\r\n        # If the module is not imported, not available and not in the online gallery then abort\r\n        throw \"Module $ModuleName not imported, not available. Please install the module using: Install-Module -Name $ModuleName -Force\"\r\n    }\r\n}\r\n\r\n# Connect to Exchange\r\ntry {\r\n    Write-Verbose \"Connecting to Exchange Online\"\r\n\r\n    # Connect to Exchange Online in an unattended scripting scenario using a certificate thumbprint (certificate has to be locally installed).\r\n    $exchangeSessionParams = @{\r\n        Organization          = $AADOrganization\r\n        AppID                 = $AADAppID\r\n        CertificateThumbPrint = $AADCertificateThumbprint\r\n        CommandName           = $commands\r\n        ShowBanner            = $false\r\n        ShowProgress          = $false\r\n        TrackPerformance      = $false\r\n        ErrorAction           = \u0027Stop\u0027\r\n    }\r\n\r\n    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams\r\n    \r\n    Write-Information \"Successfully connected to Exchange Online\"\r\n}\r\ncatch {\r\n    $ex = $PSItem\r\n    if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n        $errorObject = Resolve-HTTPError -Error $ex\r\n\r\n        $verboseErrorMessage = $errorObject.ErrorMessage\r\n\r\n        $auditErrorMessage = $errorObject.ErrorMessage\r\n    }\r\n\r\n    # If error message empty, fall back on $ex.Exception.Message\r\n    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n        $verboseErrorMessage = $ex.Exception.Message\r\n    }\r\n    if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n        $auditErrorMessage = $ex.Exception.Message\r\n    }\r\n\r\n    Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n    throw \"Error connecting to Exchange Online. Error Message: $auditErrorMessage\"\r\n}\r\n\r\ntry {\r\n    # Check if Mail Contact already exists (should only occur on a retry of task)\r\n    try {\r\n        Write-Verbose \"Querying Exchange Online mail contact with ExternalEmailAddress \u0027$ExternalEmailAddress\u0027 OR Alias \u0027$Alias\u0027 OR Name \u0027$Name\u0027\"\r\n\r\n        $mailContact = Get-MailContact -Filter \"ExternalEmailAddress -eq \u0027$ExternalEmailAddress\u0027 -or Alias -eq \u0027$Alias\u0027 -or Name -eq \u0027$Name\u0027\"\r\n\r\n        Write-Information \"Successfully queried Exchange Online mail contact with ExternalEmailAddress \u0027$ExternalEmailAddress\u0027 OR Alias \u0027$Alias\u0027 OR Name \u0027$Name\u0027. Result count: $($mailContact.GUID.Count)\"\r\n    }\r\n    catch {\r\n        $ex = $PSItem\r\n        if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n            $errorObject = Resolve-HTTPError -Error $ex\r\n    \r\n            $verboseErrorMessage = $errorObject.ErrorMessage\r\n    \r\n            $auditErrorMessage = $errorObject.ErrorMessage\r\n        }\r\n    \r\n        # If error message empty, fall back on $ex.Exception.Message\r\n        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n            $verboseErrorMessage = $ex.Exception.Message\r\n        }\r\n        if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n            $auditErrorMessage = $ex.Exception.Message\r\n        }\r\n\r\n        Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n        throw \"Error creating mail contact with the following parameters: $($mailContactParams|ConvertTo-Json). Error Message: $auditErrorMessage\"\r\n\r\n        # Clean up error variables\r\n        Remove-Variable \u0027verboseErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n        Remove-Variable \u0027auditErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n    }\r\n\r\n    if ($null -ne $mailContact.GUID) {\r\n        Write-Warning \"Found existing mail contact with ExternalEmailAddress \u0027$ExternalEmailAddress\u0027 OR Alias \u0027$Alias\u0027 OR Name \u0027$Name\u0027. Updating existing mail contact.\"\r\n    }\r\n    else {\r\n        # Create Mail Contact\r\n        try {\r\n            Write-Verbose \"Creating mail contact \u0027$($Name)\u0027 with ExternalEmailAddress \u0027$($ExternalEmailAddress)\u0027\"\r\n\r\n            $mailContactParams = @{\r\n                Name                 = $Name\r\n                FirstName            = $FirstName\r\n                Initials             = $Initials\r\n                LastName             = $LastName\r\n                Alias                = $Alias\r\n        \r\n                ExternalEmailAddress = $ExternalEmailAddress\r\n            }\r\n            $mailContactParams = Remove-EmptyValuesFromHashtable $mailContactParams\r\n\r\n            $mailContact = New-MailContact @mailContactParams -ErrorAction Stop\r\n\r\n            Write-Information \"Successfully created mail contact with the following parameters: $($mailContactParams|ConvertTo-Json)\"\r\n            $Log = @{\r\n                Action            = \"CreateAccount\" # optional. ENUM (undefined = default) \r\n                System            = \"ExchangeOnline\" # optional (free format text) \r\n                Message           = \"Successfully created mail contact with the following parameters: $($mailContactParams|ConvertTo-Json)\" # required (free format text) \r\n                IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) \r\n                TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) \r\n            }\r\n            #send result back\r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n        }\r\n        catch {\r\n            $ex = $PSItem\r\n            if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n                $errorObject = Resolve-HTTPError -Error $ex\r\n        \r\n                $verboseErrorMessage = $errorObject.ErrorMessage\r\n        \r\n                $auditErrorMessage = $errorObject.ErrorMessage\r\n            }\r\n        \r\n            # If error message empty, fall back on $ex.Exception.Message\r\n            if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                $verboseErrorMessage = $ex.Exception.Message\r\n            }\r\n            if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                $auditErrorMessage = $ex.Exception.Message\r\n            }\r\n    \r\n            $Log = @{\r\n                Action            = \"CreateAccount\" # optional. ENUM (undefined = default) \r\n                System            = \"ExchangeOnline\" # optional (free format text) \r\n                Message           = \"Error creating mail contact with the following parameters: $($mailContactParams|ConvertTo-Json). Error Message: $auditErrorMessage\" # required (free format text) \r\n                IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                TargetDisplayName = $([string]$mailContactParams.Name) # optional (free format text) \r\n                TargetIdentifier  = $([string]$mailContactParams.ExternalEmailAddress) # optional (free format text) \r\n            }\r\n            #send result back  \r\n            Write-Information -Tags \"Audit\" -MessageData $log\r\n    \r\n            Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n            throw \"Error creating mail contact with the following parameters: $($mailContactParams|ConvertTo-Json). Error Message: $auditErrorMessage\"\r\n    \r\n            # Clean up error variables\r\n            Remove-Variable \u0027verboseErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n            Remove-Variable \u0027auditErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n        }\r\n    }\r\n\r\n    # Optionally, update Mail Contact\r\n    try {\r\n        Write-Verbose \"Updating mail contact \u0027$($MailContact.Identity)\u0027\"\r\n\r\n        $mailContactUpdateParams = @{\r\n            Identity          = $MailContact.Guid\r\n            CustomAttribute15 = \u0027VEC\u0027\r\n        }\r\n    \r\n        if ($HiddenFromAddressListsBoolean -eq \u0027true\u0027) {\r\n            $mailContactUpdateParams.Add(\u0027HiddenFromAddressListsEnabled\u0027, $true)\r\n        }\r\n    \r\n        $mailContactUpdateParams = Remove-EmptyValuesFromHashtable $mailContactUpdateParams\r\n\r\n        $updatedMailContact = Set-MailContact @mailContactUpdateParams -ErrorAction Stop\r\n\r\n        Write-Information \"Successfully updated mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json)\"\r\n        $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"ExchangeOnline\" # optional (free format text) \r\n            Message           = \"Successfully updated mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json)\" # required (free format text) \r\n            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) \r\n            TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n    }\r\n    catch {\r\n        $ex = $PSItem\r\n        if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n            $errorObject = Resolve-HTTPError -Error $ex\r\n    \r\n            $verboseErrorMessage = $errorObject.ErrorMessage\r\n    \r\n            $auditErrorMessage = $errorObject.ErrorMessage\r\n        }\r\n    \r\n        # If error message empty, fall back on $ex.Exception.Message\r\n        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n            $verboseErrorMessage = $ex.Exception.Message\r\n        }\r\n        if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n            $auditErrorMessage = $ex.Exception.Message\r\n        }\r\n\r\n        $Log = @{\r\n            Action            = \"UpdateAccount\" # optional. ENUM (undefined = default) \r\n            System            = \"ExchangeOnline\" # optional (free format text) \r\n            Message           = \"Error updating mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json). Error Message: $auditErrorMessage\" # required (free format text) \r\n            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n            TargetDisplayName = $([string]$MailContact.Guid) # optional (free format text) \r\n            TargetIdentifier  = $([string]$MailContact.DisplayName) # optional (free format text) \r\n        }\r\n        #send result back  \r\n        Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n        Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n        throw \"Error updating mail contact with the following parameters: $($mailContactUpdateParams|ConvertTo-Json). Error Message: $auditErrorMessage\"\r\n\r\n        # Clean up error variables\r\n        Remove-Variable \u0027verboseErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n        Remove-Variable \u0027auditErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n    }\r\n\r\n    # Optionally, add Mail Contact to group(s)\r\n    if ($null -ne $GroupsToAdd) {\r\n        foreach ($groupToAdd in $GroupsToAdd) {\r\n            try {\r\n                Write-Verbose \"Adding mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027\"\r\n\r\n                $mailContactAddToGroupParams = @{\r\n                    Identity                        = $groupToAdd.guid\r\n                    Member                          = $MailContact.Guid\r\n                    BypassSecurityGroupManagerCheck = $true\r\n                    Confirm                         = $false\r\n                }\r\n            \r\n                $mailContactAddToGroupParams = Remove-EmptyValuesFromHashtable $mailContactAddToGroupParams\r\n\r\n                $mailContactAddedToGroup = Add-DistributionGroupMember @mailContactAddToGroupParams -ErrorAction Stop\r\n\r\n                Write-Information \"Successfully added mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027\"\r\n                $Log = @{\r\n                    Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                    System            = \"ExchangeOnline\" # optional (free format text) \r\n                    Message           = \"Successfully added mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027\" # required (free format text) \r\n                    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                    TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) \r\n                    TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) \r\n                }\r\n                #send result back  \r\n                Write-Information -Tags \"Audit\" -MessageData $log\r\n            }\r\n            catch {\r\n                $ex = $PSItem\r\n                if ( $($ex.Exception.GetType().FullName -eq \u0027Microsoft.PowerShell.Commands.HttpResponseException\u0027) -or $($ex.Exception.GetType().FullName -eq \u0027System.Net.WebException\u0027)) {\r\n                    $errorObject = Resolve-HTTPError -Error $ex\r\n            \r\n                    $verboseErrorMessage = $errorObject.ErrorMessage\r\n            \r\n                    $auditErrorMessage = $errorObject.ErrorMessage\r\n                }\r\n            \r\n                # If error message empty, fall back on $ex.Exception.Message\r\n                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {\r\n                    $verboseErrorMessage = $ex.Exception.Message\r\n                }\r\n                if ([String]::IsNullOrEmpty($auditErrorMessage)) {\r\n                    $auditErrorMessage = $ex.Exception.Message\r\n                }\r\n\r\n                if ($auditErrorMessage -like \"*already a member of the group*\") {\r\n                    Write-Information \"Successfully added mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027 (already a member)\"\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = \"Successfully added mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027 (already a member)\" # required (free format text) \r\n                        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $([string]$mailContact.DisplayName) # optional (free format text) \r\n                        TargetIdentifier  = $([string]$mailContact.Guid) # optional (free format text) \r\n                    }\r\n                    #send result back  \r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n                }\r\n                else{\r\n                    $Log = @{\r\n                        Action            = \"GrantMembership\" # optional. ENUM (undefined = default) \r\n                        System            = \"ExchangeOnline\" # optional (free format text) \r\n                        Message           = \"Error adding mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027. Error Message: $auditErrorMessage\" # required (free format text) \r\n                        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) \r\n                        TargetDisplayName = $([string]$MailContact.Guid) # optional (free format text) \r\n                        TargetIdentifier  = $([string]$MailContact.DisplayName) # optional (free format text) \r\n                    }\r\n                    #send result back  \r\n                    Write-Information -Tags \"Audit\" -MessageData $log\r\n\r\n                    Write-Verbose \"Error at Line \u0027$($ex.InvocationInfo.ScriptLineNumber)\u0027: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)\"\r\n                    Write-Error \"Error adding mail contact \u0027$($MailContact.Identity)\u0027 to group \u0027$($groupToAdd.id) ($($groupToAdd.guid))\u0027. Error Message: $auditErrorMessage\" # Not a critical error\r\n                }\r\n\r\n                # Clean up error variables\r\n                Remove-Variable \u0027verboseErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n                Remove-Variable \u0027auditErrorMessage\u0027 -ErrorAction SilentlyContinue\r\n            }\r\n        }\r\n    }\r\n}\r\nfinally {\r\n    Write-Verbose \"Disconnection from Exchange Online\"\r\n    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop    \r\n    Write-Information \"Successfully disconnected from Exchange Online\"\r\n}","runInCloud":false}
'@ 

Invoke-HelloIDDelegatedForm -DelegatedFormName $delegatedFormName -DynamicFormGuid $dynamicFormGuid -AccessGroups $delegatedFormAccessGroupGuids -Categories $delegatedFormCategoryGuids -UseFaIcon "True" -FaIcon "fa fa-user-plus" -task $tmpTask -returnObject ([Ref]$delegatedFormRef) 
<# End: Delegated Form #>

