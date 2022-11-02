<!-- Requirements -->
## Requirements
This HelloID Service Automation Delegated Form uses the [Exchange Online PowerShell V2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides Exchange Online (Office365) mail contact functionality. The following steps will be performed:
 1. Enter mail contact details
 2. Optionally, Select the groups to add the mail contact to
 3. After confirmation the mail contact is created and optionally added to the specified group(s)

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2022/11/02  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Requirements](#requirements)
- [Description](#description)
- [Versioning](#versioning)
- [Table of Contents](#table-of-contents)
- [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
- [Requirements](#requirements-1)
- [Getting started](#getting-started)
- [Installing the Microsoft Exchange Online PowerShell V2 module](#installing-the-microsoft-exchange-online-powershell-v2-module)
- [Creating the Azure AD App Registration and certificate](#creating-the-azure-ad-app-registration-and-certificate)
  - [Application Registration](#application-registration)
  - [Configuring App Permissions](#configuring-app-permissions)
  - [Generate a self-signed certificate](#generate-a-self-signed-certificate)
  - [Attach the certificate to the Azure AD application](#attach-the-certificate-to-the-azure-ad-application)
  - [Assign Azure AD roles to the application](#assign-azure-ad-roles-to-the-application)
  - [Authentication and Authorization](#authentication-and-authorization)
- [Post-setup configuration](#post-setup-configuration)
- [Manual resources](#manual-resources)
  - [Powershell data source '[powershell-datasource]_Exchange-Online-Contact-create-check-names'](#powershell-data-source-powershell-datasource_exchange-online-contact-create-check-names)
  - [Powershell data source '[powershell-datasource]_Exchange-Online-group-emailaddresses-uniqueness-check'](#powershell-data-source-powershell-datasource_exchange-online-group-emailaddresses-uniqueness-check)
  - [Powershell data source '[powershell-datasource]_Exchange-Online-group-generate-table'](#powershell-data-source-powershell-datasource_exchange-online-group-generate-table)
  - [Delegated form task '[task]_Exchange Online - Contact - Create'](#delegated-form-task-task_exchange-online---contact---create)
- [Getting help](#getting-help)
- [Getting help](#getting-help-1)
- [HelloID Docs](#helloid-docs)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


## Requirements
- Installed and available [Microsoft Exchange Online PowerShell V2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)
- To manage users, mailboxes and groups, the service account has to have the role "**Exchange Administrator**" assigned.
- Required to run **On-Premises** since it is not allowed to import a module with the Cloud Agent.
- **Concurrent sessions** in HelloID set to a **maximum of 1**! If this is any higher than 1, this may cause errors, since Exchange only support a maximum of 3 sessions per minute.
- Since we create a Remote PS Session on the agent server (which will containt the Exchange Session, to avoid the Exchange limit of 3 sessions per minute), the service account has to be a member of the group “**Remote Management Users**”.
- An __App Registration in Azure AD__ is required. __Please follow the [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#step-3-generate-a-self-signed-certificate:~:text=Appendix-,Step%201%3A%20Register%20the%20application%20in%20Azure%20AD,-Note) as reference to configure the App Registration correctly__


## Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

<!-- GETTING STARTED -->
## Installing the Microsoft Exchange Online PowerShell V2 module
By using this connector you will have the ability to manage groupmemberships and/or ownerships to a group.
Since we use the cmdlets from the Microsoft Exchange Online PowerShell V2 module, it is required this module is installed and available for the service account.
Please follow the [Microsoft documentation on how to install the module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-the-exo-v2-module). 


## Creating the Azure AD App Registration and certificate
> _The steps below are based on the [Microsoft documentation](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps) as of the moment of release. The Microsoft documentation should always be leading and susceptible to change. The steps below might not reflect those changes._

### Application Registration
The first step is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to Exchange and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>ExO PowerShell CBA</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory > App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Office 365 Exchange Online</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Manage Exchange As Application <b><i>Exchange.ManageAsApp</i></b>
> _The Office 365 Exchange Online might not be a selectable API. In thise case, select "APIs my organization uses" and search here for "Office 365 Exchange Online"__

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

### Generate a self-signed certificate
For app-only authentication in Azure AD, you typically use a certificate to request access. Anyone who has the certificate and its private key can use the app, and the permissions granted to the app.
Create and configure a self-signed X.509 certificate, which will be used to authenticate your Application against Azure AD, while requesting the app-only access token.
The fastest and recommened way to do so is by using the script below:

```
$dnsName = "contoso.org"
$password = "P@ssw0Rd1234"

# Create certificate
$mycert = New-SelfSignedCertificate -DnsName $dnsName -CertStoreLocation "cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(1) -KeySpec KeyExchange

# Export certificate to .pfx file
$mycert | Export-PfxCertificate -FilePath mycert.pfx -Password $(ConvertTo-SecureString -String $password -AsPlainText -Force)

# Export certificate to .cer file
$mycert | Export-Certificate -FilePath mycert.cer
```

### Attach the certificate to the Azure AD application
To attach your certificate to your application, navigate to <b>Azure Portal > Azure Active Directory > App Registrations</b>.
Select the application we created before, and select “<b>Certificates & secrets</b>”.
On the Certificates & secrets page that opens, click the “<b>Upload certificate</b>” button.
In the dialog that opens, browse to the self-signed certificate (.cer file) that we created before.
When you're finished, click Add.
The certificate is now shown in the Certificates section.

### Assign Azure AD roles to the application
Azure AD has more than 50 admin roles available. The Global Administrator and Exchange Administrator roles provide the required permissions for any task in Exchange Online PowerShell. For general instructions about assigning roles in Azure AD, see [View and assign administrator roles in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal).

To assign the role(s) to your application, navigate to <b>Azure Portal > Azure Active Directory > Roles and administrators</b>.
On the Roles and administrators page that opens, find and select one of the supported roles e.g. “<b>Exchange Administrator</b>” by clicking on the name of the role (not the check box) in the results.
On the Assignments page that opens, click the “<b>Add assignments</b>” button.
In the Add assignments flyout that opens, find and select the app that we created before.
When you're finished, click Add.
Back on the Assignments page, verify that the app has been assigned to the role.

### Authentication and Authorization
There are multiple ways to authenticate to Exchange Online using a certificate with each has its own pros and cons, in this example we are using the option where we connect using a certificate thumbprint and therefore the Certificate has to be locally installed.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to get the <b>Certificate Thumbprint</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Certificates” copy the value of the “<b>Thumbprint</b>”.
*	At last we need to <b>install the certificate on the HelloID Agent server</b>. This has to be locally installed since we work with the thumbprint only and not the certificate itself.
 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)

| Variable name                             | Description                                   | Example value     |
| ----------------------------------------- | --------------------------------------------- | ----------------- |
| AADExchangeOrganization               | The name of the organization to connect to and where the Azure AD App Registration exist                        | enyoi.onmicrosoft.com   |
| AADExchangeAppID               | The Application (client) ID of the Azure AD App Registration with Exchange Permissions. __Please follow the [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#step-3-generate-a-self-signed-certificate:~:text=Appendix-,Step%201%3A%20Register%20the%20application%20in%20Azure%20AD,-Note) as reference to configure the App Registration correctly__                       | 12345678-7a40-4882-8db2-abcdefghijkl          |
| Azure AD Certificate Thumbprint | The thumbprint of the certificate that is linked to the Azure AD App Registration __Please note: This certificate has to be locally installed__| ********          |


## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source '[powershell-datasource]_Exchange-Online-Contact-create-check-names'
This Powershell data source checks if the email address is free to use.

### Powershell data source '[powershell-datasource]_Exchange-Online-group-emailaddresses-uniqueness-check'
This Powershell data source checks if the email address is free to use.

### Powershell data source '[powershell-datasource]_Exchange-Online-group-generate-table'
This Powershell data source queries and returns the groups.

### Delegated form task '[task]_Exchange Online - Contact - Create'
This delegated form task will update the group members and/or owners.

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012518799-How-to-add-a-target-system) pages_

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/1184-helloid-sa-exchange-online-create-mail-contact)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/