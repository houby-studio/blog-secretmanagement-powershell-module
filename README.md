# Blog - SecretManagement PowerShell module

## Introduction

As a reaction to [reddit thread](https://reddit.com/r/PowerShell/comments/p503ym/for_those_using_secretsmanagement_module_to/) I have encountered today, I have decided to write short blog with real life example, showing what I have already done with the new module to adopt it in our company.

In this blog I will use the new [SecreManagement](https://devblogs.microsoft.com/powershell/secretmanagement-and-secretstore-are-generally-available/) module with two other amazing things I have recently started using everywhere. It is [Just Enough Administration (JEA)](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.1) and [Group Managed Service Accounts (gMSA)](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview).

As it turns out, you can create very tight and secure setups, which enables users or automated tasks to perform exactly what you need it to and nothing else.

*Note: All files used in this example are available in their final form in this repository.*

## Prerequisites

For this example, I assume that you have Active Directory site with domain joined systems, where we will want to run our PowerShell functions.

* You need to be able to create **gMSA** account, which requires some [setup as described here](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts).  
*Note: You need to be member of the **Domain Admin***.
* You need to be able to create and [register JEA session configurations](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/register-jea?view=powershell-7.1) on target computer.  
*Note: You need to be member of the local group **Administrators** on target computer*.
* You need to be able to install [SecretManagement module](https://www.powershellgallery.com/packages/Microsoft.PowerShell.SecretManagement) and [CredMan module](https://www.powershellgallery.com/packages/SecretManagement.JustinGrote.CredMan).  
*Note: You need to be able to access PowerShell Gallery to download it either via PowerShell or via browser.*

## Getting started

For the sake of simplicity, we won't create PowerShell module, which usually contains JEA session and role configuration files. We will create folder with those files on disk and we will use only commonly available commands. Everything we execute below is executed on target computer, let's call it **Srv001** in the domain **contoso.com** (Change according to you environment).

### Install required modules

Note: You may need to register PSGallery to be able to download following modules as described on [Microsoft docs](https://docs.microsoft.com/en-us/powershell/scripting/gallery/installing-psget?view=powershell-7).

Start elevated PowerShell and run following commands:

```powershell
# BEWARE: You need to run this only on computer, which does NOT not have enabled PowerShellGet just yet.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PowerShellGet -Force -AllowClobber
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Install only required modules for this example.
Install-Module -Name 'Microsoft.PowerShell.SecretManagement','SecretManagement.JustinGrote.CredMan' -Scope AllUsers
```

### Create gMSA account for JEA

gMSA is great in many ways. We can use it to to run services like SQL Agent under that identity or in our case, run commands in JEA session under this account. No one needs to know this password. AD manages its passwords and their rotation just like with computer accounts.

Start PowerShell with your domain admin account and run following commands:

```powershell
# Supply account name, description and domain computer allowed to login with this account
$GMSAName = 'JEA_Dl_Prv_File'
$GMSADescription = 'This gMSA account runs in JEA session designated to download file from authenticated website.'
$JEAEndpoint = 'Srv001$'

# Create gMSA
New-ADServiceAccount -Name $GMSAName -DNSHostName "$GMSAName.contoso.com" -PrincipalsAllowedToRetrieveManagedPassword $JEAEndpoint -Description $GMSADescription
```

### Create JEA session configuration and JEA role files

*Note: You can refer to this documentation on what we exactly create with [role](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/role-capabilities?view=powershell-7.1) and [session configuration](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/session-configurations?view=powershell-7.1) files.*

Start PowerShell and run following commands:

```powershell
# Create folder for JEA files
New-Item -Path "C:\" -Name "JEA" -ItemType Directory
# Create new role for limited user or automation service
New-PSRoleCapabilityFile -Path "C:\JEA\LimitedUser.psrc"
# Create new role for administrator, who is able to set credentials
New-PSRoleCapabilityFile -Path "C:\JEA\SecretManager.psrc"
# Create new session configuration, which will contain both roles
New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer -Path "C:\JEA\DownloadPrivateFile.pssc" -GroupManagedServiceAccount "CONTOSO\JEA_Dl_Prv_File"
```

### Create AD security groups

We will create two AD groups. Members of the group `CONTOSO\DownloadPrivateFile` will be able to run the limited user command to download file from the website and members of the `CONTOSO\SecretManager` will be able to run command to set credentials used to access protected website.

Start PowerShell with your domain admin account and run following commands:

```powershell
# Create AD Group allowed to access JEA Endpoint and download files from website
$NewGroup = 'DownloadPrivateFile'
New-ADGroup -DisplayName $NewGroup -Name $NewGroup -GroupCategory Security -GroupScope Global -Path 'OU=JEA Security Groups,DC=Contoso,DC=com'

# Create AD Group allowed to access JEA Endpoint and update credentials
$NewGroup = 'SecretManager'
New-ADGroup -DisplayName $NewGroup -Name $NewGroup -GroupCategory Security -GroupScope Global -Path 'OU=JEA Security Groups,DC=Contoso,DC=com'
```

### JEA session configuration file

*Note: You can check [entire file in this repository](JEA/DownloadPrivateFile.pssc).*

We have our basic template created in `C:\JEA\DownloadPrivateFile.pssc`, let's edit it to include both role definitions.

```powershell
RoleDefinitions = @{ 'CONTOSO\DownloadPrivateFile' = @{ RoleCapabilityFiles = 'C:\JEA\LimitedUser.psrc' }; 'CONTOSO\SecretManager' = @{ RoleCapabilityFiles = 'C:\JEA\SecretManager.psrc' } }
```

### JEA role file for LimitedUser

*Note: You can check [entire file in this repository](JEA/LimitedUser.psrc).*

We have our basic template created in `C:\JEA\LimitedUser.psrc`. Let's edit it to:

* Define module `Microsoft.PowerShell.SecretManagement` to be imported inside this session
* Define command `Get-PrivateFile` to be visible to user inside this session
* Define command `Get-PrivateFile` inside scriptblock, which is the command to download required file

```powershell
ModulesToImport  = 'Microsoft.PowerShell.SecretManagement'

VisibleFunctions = @{ Name = 'Get-PrivateFile'; Parameters = @{ Name = 'Url' } }

FunctionDefinitions = @{ Name = 'Get-PrivateFile'; ScriptBlock = { 
    param($Url)
    $Name = 'WebCredential'
    $VaultName = 'Get-PrivateFile'
    $Credential = Get-Secret -Name $Name -Vault $VaultName

    Invoke-WebRequest -Uri $Url -Credential $Credential -OutFile 'C:\Report\file.txt'
  } 
}
```

### JEA role file for SecretManager

*Note: You can check [entire file in this repository](JEA/SecretManager.psrc).*

We have our basic template created in `C:\JEA\SecretManager.psrc`. Let's edit it to:

* Define module `Microsoft.PowerShell.SecretManagement` to be imported inside this session
* Define command `Set-WebsiteCredential` to be visible to user inside this session
* Define command `Set-WebsiteCredential` inside scriptblock, which is the command to set credential for limited user to use

```powershell
ModulesToImport  = 'Microsoft.PowerShell.SecretManagement'

VisibleFunctions = @{ Name = 'Set-WebsiteCredential'; Parameters = @{ Name = 'Credential' } }

FunctionDefinitions = @{ Name = 'Set-WebsiteCredential'; ScriptBlock = { 
    param($Credential)

    $Name = 'WebCredential'
    $VaultName = 'Get-PrivateFile'
    $ModuleName = 'SecretManagement.JustinGrote.CredMan'

    if (-not (Get-SecretVault | Where-Object Name -EQ $VaultName)) {
      Register-SecretVault -Name $VaultName -ModuleName $ModuleName
    }
    Set-Secret -Name $Name -Vault $VaultName -Secret $Credential
  } 
}
```

### Register JEA session configuration

We are ready to deploy our configuration, let's execute following command to register our JEA session configuration on our endpoint computer.


Start elevated PowerShell and run following command:

```powershell
Register-PSSessionConfiguration -Path 'C:\JEA\DownloadPrivateFile.pssc' -Name 'contoso.example.downloadprivatefile'
```

### Assign roles to domain users

In our example we will assign roles to the following users.

* User `CONTOSO\user` will be able to run `Get-PrivateFile` to download file from website. Add this user to AD group `CONTOSO\DownloadPrivateFile`.
* User `CONTOSO\admin` will be able to run `Set-WebsiteCredential` to set credential for end user to use. Add this user to AD group `CONTOSO\SecretManager`.

### Set credential

User `CONTOSO\admin` can now launch PowerShell and set credential by using following commands.

Start PowerShell under `CONTOSO\admin` user context and run following commands:

```powershell
$Credential = Get-Credential
Invoke-Command -ComputerName 'Srv001' -ConfigurationName 'contoso.example.downloadprivatefile' -ScriptBlock { Set-WebsiteCredential -Credential $args[0] } -ArgumentList $Credential
```

**Beauty** of this is that even this admin is not able to retrieve credentials, only update them if they ever change. He is also not able to run command to download file from the website.

### Download file

User `CONTOSO\user` can now launch PowerShell and download file using following command.  

Start PowerShell under `CONTOSO\user` user context and run following command:

```powershell
Invoke-Command -ComputerName 'Srv001' -ConfigurationName 'contoso.example.downloadprivatefile' -ScriptBlock { Get-PrivateFile -Url 'https://contoso.com/private/file.txt' }
```

**Beauty** of this is that this user doesn't need to and even cannot obtain the credentials or use them for anything else than it was designed for.  
This can be used aswell in **scheduled task** or as step in **SQL job** or any other **AUTOMATED TASK**. Just add said account, which runs the task/service/whatever, to security group `CONTOSO\DownloadPrivateFile` and voila, it can execute without exposing or passing credentials in any way!

## Conclusion

I truly hope I have made my use case clear and understandable with this example.  
And even more I hope you will use it in similar manner in your environment. If you do, please let me know!
