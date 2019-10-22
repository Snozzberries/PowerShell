# ADRecon.ps1
# https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1
# AAD Connect MA Documenter
# https://github.com/Microsoft/AADConnectConfigDocumenter

iex (iwr https://raw.githubusercontent.com/Snozzberries/PowerShell/master/New-FlatObject.ps1 -UseBasicParsing).content

<# Windows #>
gwmi Win32_OperatingSystem | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-OperatingSystem.csv
gwmi Win32_ComputerSystem | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-ComputerSystem.csv

gwmi Win32_Product | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Software.csv
# Does not work in Windows, only Windows Server, use DISM on Windows OS
Get-WindowsFeature | ? { $_.InstallState -eq "Installed" } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Features.csv
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AvailableUpdates.csv
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().QueryHistory(0, (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().GetTotalHistoryCount()) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-UpdateHistory.csv

wevtutil.exe epl Application $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-ApplicationLog.evtx /q:"*[System[(Level=1 or Level=2 or Level=3)]]"
wevtutil.exe epl System $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SystemLog.evtx /q:"*[System[(Level=1 or Level=2 or Level=3)]]"

Get-NetFirewallProfile | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-NetFirewallProfile.csv
gwmi Win32_Service | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Services.csv

get-smbshare | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Shares.csv

Get-NetAdapter | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Adapters.csv
Get-NetIPAddress | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Addresses.csv
Get-NetIPInterface | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-DhcpState.csv
Get-NetTCPConnection | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-NetTcpConnection.csv
Get-DnsClientServerAddress | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Dns.csv

Get-ScheduledTask | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Tasks.csv

gwmi Win32_UserAccount -Filter "LocalAccount='True'" | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-LocalUsers.csv
gwmi Win32_Group -Filter "LocalAccount='True'" | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-LocalGroups.csv
Get-LocalGroup | % { Get-LocalGroupMember -Name $_ | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Members-$($_.Name).csv }
#gwmi Win32_Group -Filter "LocalAccount='True'"|%{$_.GetRelated("Win32_UserAccount")|New-FlatObject|Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Members-$($_.Name).csv}

w32tm /query /status > $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Time.txt

Get-BpaModel | % { $_.id; Invoke-BpaModel -ModelId $_.id; Get-BpaResult -ModelId $_.id | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-BPA-$($_.Id.Substring($_.Id.LastIndexOf('/')+1)).csv }

Get-Disk | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Disks.csv
Get-Partition | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Partitions.csv
Get-Volume | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Volumes.csv

(Get-WinEvent -ListLog *) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-ListLog.csv
wevtutil.exe epl Security $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SecLog90Day.evtx /q:"""*[System[TimeCreated[timediff(@SystemTime) <= $((New-TimeSpan -End (Get-Date) -Start (Get-Date).AddDays(-90)).TotalMilliseconds)]]]"""

Get-Process | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Processes.csv

Get-GPResultantSetOfPolicy -ReportType Html -Path $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.html; Get-GPResultantSetOfPolicy -ReportType Xml -Path $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.xml
#gpresult.exe /h $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.html;gpresult.exe /x $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.xml

<# O365 #>
#Prep
$creds = Get-Credential
Install-Module MSOnline
Install-Module Az
Install-Module AzureAD
Import-Module MSOnline
Import-Module Az
Import-Module AzureAD
Connect-MSOnline -Credential $creds
Connect-AzAccount -Credential $creds
Connect-AzureAD -Credential $creds
Get-MsolAccountSku | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-AccountSku.csv
Get-MsolCompanyInformation | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-CompanyInfo.csv
Get-MsolContact | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Contact.csv
Get-MsolDevice -All | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Devices.csv
Get-MsolDomain | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Domain.csv
Get-MsolGroup -All | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Groups.csv
Get-MsolHasObjectsWithDirSyncProvisioningErrors | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-SyncErrors.csv
Get-MsolPartnerInformation | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-PartnerInfo.csv
Get-MsolRole | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Roles.csv
Get-MsolRole | ? { $_.Name -like "*Admin*" -or $_.Name -like "*Oper*" -or $_.Name -like "*Global*" } | % { Get-MsolRoleMember -RoleObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Role-$($_.Name).csv }
Get-MsolServicePrincipal | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-ServicePrincipals.csv
Get-MsolSubscription | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Subscription.csv
Get-MsolUser | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Users.csv
Get-MsolUserByStrongAuthentication | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-StrongAuthN.csv
Get-MsolDirSyncConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-DirSyncConfig.csv
Get-MsolDirSyncFeatures | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-Features.csv
Get-MsolDomain | % { Get-MsolDomainFederationSettings -DomainName $_.name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-FederationSettings-$($_.Name).csv }
Get-MsolDomain | % { Get-MsolDomainVerificationDns -DomainName $_.name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-VerificationDns-$($_.Name).csv }
Get-MsolDomain | % { Get-MsolPasswordPolicy -DomainName $_.name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-MSOL-PasswordPolicy-$($_.Name).csv }
Get-AzTenant | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AZ-Tenant.csv
Get-AzEnrollmentAccount | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AZ-EnrollmentAccount.csv
$AadApplications = Get-AzureADApplication -All $true
$AadApplications | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Applications.csv
$AadApplications | %{ Get-AzureADApplicationOwner -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ApplicationOwner-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadApplications | %{ Get-AzureADApplicationExtensionProperty -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ApplicationExtension-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadApplications | %{ Get-AzureADApplicationKeyCredential -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ApplicationKeyCred-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadApplications | %{ Get-AzureADApplicationPasswordCredential -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ApplicationPassCred-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadApplications | %{ Get-AzureADApplicationServiceEndpoint -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ApplicationServiceEndpoint-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadContacts = Get-AzureADContact
$AadContacts | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Contacts.csv
$AadContacts | %{ Get-AzureADContactDirectReport -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ContactDirectReport-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadContacts | %{ Get-AzureADContactManager -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ContactManager-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$AadContacts | %{ Get-AzureADContactMembership -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ContactMembership-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
Get-AzureADContract -All $true | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Contract.csv
Get-AzureADCurrentSessionInfo | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-CurrentSession.csv
Get-AzureADDeletedApplication | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DeletedApplication.csv
$AadDevices = Get-AzureADDevice
$AadDevices | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Devices.csv
$AadDevices | %{ Get-AzureADDeviceRegisteredOwner -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DeviceRegisteredOwners.csv
$AadDevices | %{ Get-AzureADDeviceRegisteredUser -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DeviceRegisteredUsers.csv
Get-AzureADDeviceConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DeviceConfig.csv
$AadRoles = Get-AzureADDirectoryRole
$AadRoles | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Roles.csv
$AadRoles | %{ Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-RoleMembers-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv }
Get-AzureADDirectoryRoleTemplate | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-RoleTemplate.csv
$AadDomains = Get-AzureADDomain
$AadDomains | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Domains.csv
Get-AzureADExtensionProperty | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ExtensionProps.csv
$AadGroups = Get-AzureADGroup
$AadGroups | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Groups.csv
$AadGroups | %{ Get-AzureADGroupAppRoleAssignment -ObjectId $_.ObjectId -All $true | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-GroupAppRole-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv }
$AadGroups | %{ Get-AzureADGroupOwner -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-GroupOwner.csv
Get-AzureADMSDeletedGroup -All $true | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DeletedGroup.csv
Get-AzureADMSGroupLifecyclePolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-GroupLifecycle.csv
$AadMSGroups = Get-AzureADMSGroup
$AadMSGroups | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-MSGroups.csv
$AadServices = Get-AzureADServicePrincipal
$AadServices | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Services.csv
$AadServices | %{ Get-AzureADServicePrincipalOwner -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceOwners.csv
$AadServices | %{ Get-AzureADServiceAppRoleAssignedTo -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceRoleAssignTo.csv
$AadServices | %{ Get-AzureADServiceAppRoleAssignment -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceRoleAssignment.csv
$AadServices | %{ Get-AzureADServicePrincipalOwnedObject -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceOwnedObjects.csv
$AadServices | %{ Get-AzureADServicePrincipalCreatedObject -ObjectId $_.ObjectId -All $true } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceCreatedObjects.csv
$AadServices | %{ Get-AzureADServicePrincipalKeyCredential -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceKeyCreds.csv
$AadServices | %{ Get-AzureADServicePrincipalPasswordCredential -ObjectId $_.ObjectId} | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServicePassCreds.csv
$AadServices | %{ Get-AzureADServicePrincipalMembership -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceMembership.csv
$AadServices | %{ Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $_.ObjectId -All $true } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ServiceGrants.csv
$AadUsers = Get-AzureADUser
$AadUsers | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Users.csv
$AadUsers | %{ Get-AzureADUserAppRoleAssignment -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserAppRole.csv
$AadUsers|%{Get-AzureADUserCreatedObject -ObjectId $_.ObjectId}| New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserCreatedObjects.csv
$AadUsers | %{ Get-AzureADUserDirectReport -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserDirectReports.csv
$AadUsers | %{ Get-AzureADUserExtension -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserExtension.csv
$AadUsers | %{ Get-AzureADUserLicenseDetail -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserLicenses.csv
$AadUsers|%{Get-AzureADUserManager -ObjectId $_.ObjectId}| New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserManager.csv
$AadUsers | %{ Get-AzureADUserMembership -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-UserMembership.csv
$AadUsers|%{Get-AzureADUserOAuth2PermissionGrant -ObjectId $_.ObjectId}| New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserGrants.csv
$AadUsers|%{Get-AzureADUserOwnedDevice -ObjectId $_.ObjectId}| New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserOwnedDevice.csv
$AadUsers | %{ Get-AzureADUserOwnedObject -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserOwnedObject.csv
$AadUsers | %{ Get-AzureADUserRegisteredDevice -ObjectId $_.ObjectId } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-UserRegDevice.csv
Get-AzureADSubscribedSku | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Skus.csv
Get-AzureADTenantDetail | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-TenantDetail.csv
Get-AzureADTrustedCertificateAuthority | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-TrustedCas.csv
Get-AzureADOAuth2PermissionGrant -All $true | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-Grants.csv
Get-AzureADMSIdentityProvider | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-MsIdP.csv
Get-AzureADApplicationProxyConnector | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-AppProxyConnector.csv
$AadApplications = Get-AzureADApplication -All $true
$AadApplications | % { Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ProxyApp-$($_.ObjectId.Substring($_.ObjectId.Length-12)).csv}
$ProxyApplications = $AadApplications|%{Get-AzureADApplicationProxyApplicationConnectorGroup -ObjectId $_.ObjectId}
$ProxyApplications | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ProxyAppGroups-$($_.Id.Substring($_.Id.Length-12)).csv
$ProxyApplications | %{ Get-AzureADApplicationProxyConnectorGroupMembers -Id $_.Id | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ProxyAppMembers-$($_.Id.Substring($_.Id.Length-12)).csv}
$ProxyApplications | %{ Get-AzureADApplicationProxyConnectorMemberOf -Id $_.Id | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-ProxyAppMemberOf-$($_.Id.Substring($_.Id.Length-12)).csv}
$AadDomains = Get-AzureADDomain
$AadDomains | %{ Get-AzureADDomainNameReference -Name $_.Name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DomainNameRef-$($_.Name).csv}
$AadDomains | %{ Get-AzureADDomainServiceConfigurationRecord -Name $_.Name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DomainServiceConfig-$($_.Name).csv}
$AadDomains | %{ Get-AzureADDomainVerificationDnsRecord -Name $_.Name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\O365-AAD-DomainVerification-$($_.Name).csv}

<# SPO//EXO//S4B #>
#Prep
$orgName="<name of your Office 365 organization, example: contosotoycompany>"
$creds = Get-Credential
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $creds -Authentication Basic -AllowRedirection
Import-PSSession $session -DisableNameChecking
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Import-Module Microsoft.Online.SharePoint.PowerShell
Connect-SPOService -Url https://$orgName-admin.sharepoint.com
$SccSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $creds -Authentication "Basic" -AllowRedirection
Import-PSSession $SccSession -Prefix cc

Get-UnifiedGroup | Where { $_.AccessType -eq "Private" } | Set-UnifiedGroup -HiddenFromAddressListsEnabled:$true
Get-SPOBrowserIdleSignOut
Get-SPOTenant
Get-SPOTenantSyncClientRestriction

Remove-PSSession $session
Remove-PSSession $SccSession
Disconnect-SPOService

<# AAD Connect #>
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1'
Import-Module ADSync
New-AzureADSSOAuthenticationContext
Get-AzureADSSOStatus | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SSO-Status.csv
Get-AzureADSSOComputerAcccountInformation | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SSO-ComputerAccount.csv
Get-ADSyncServerConfiguration -Path $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-ServerConfig\
Get-ADSyncAADCompanyFeature | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-Feature.csv
Get-ADSyncAutoUpgrade | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-AutoUpgrade.csv
Get-ADSyncConnector | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-Connector.csv
Get-ADSyncConnectorTypes | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-ConnectorTypes.csv
Get-ADSyncDatabaseConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-Database.csv
Get-ADSyncGlobalSettingsParameter | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-GlobalSettings.csv
Get-ADSyncPartitionPasswordSyncState | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-PasswordSync.csv
Get-ADSyncRunProfileResult | ? { $_.Result -ne "success" } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-RunProfileResults.csv
Get-ADSyncScheduler | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-Scheduler.csv
Get-ADSyncSchedulerConnectorOverride | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-SchedulerOverride.csv
Get-ADSyncSchema | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-Schema.csv
Get-ADSyncADConnectorAccount | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SYNC-ConnectorAccount.csv
Get-ADSyncADConnectorAccount | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SYNC-DisableInheritance.csv
Get-ADSyncConnector | ? { $_.Name -like "*AAD" } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SYNC-AAD.csv
Get-ADSyncConnector | ? { $_.Type -eq "AD" } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SYNC-AD.csv
Get-ADSyncAADPasswordResetConfiguration -Connector (Get-ADSyncConnector | ? { $_.Name -like "*AAD" }).Name | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SYNC-SSPR.csv

#Get-ADUser -Filter 'name -like "svc.ad.adconnect"'|Get-ADPrincipalGroupMembership|select Name
#Get-ADUser -Filter "Name -like 'svc.ad.*'" -Properties passwordLastSet|select name,password*

<# ADFS #>
Import-Module Adfs
Get-Command -Module ADFS Get-* | % { iex $_.Name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-ADFS-$($_.Name.Substring(4)).csv }
gci Cert:\LocalMachine\My | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-Certificates.csv
gci -Recurse HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL > $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SCHANNEL.txt
gci -Recurse HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local > $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-TLS.txt
gci -Recurse HKLM:\SOFTWARE\Microsoft\.NETFramework > $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-DotNet.txt
gci -Recurse HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SCHANNEL.txt
gci -Recurse HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-TLS.txt
gci -Recurse HKLM:\SOFTWARE\Microsoft\.NETFramework | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-DotNet.txt


<# WAP #>
gc C:\Windows\System32\drivers\etc\hosts > $env:USERPROFILE\Desktop\hosts.txt
gci Cert:\LocalMachine\my | fl * > $env:USERPROFILE\Desktop\LocalMachineCerts.txt
Invoke-BpaModel Microsoft/Windows/RemoteAccessServer
Get-BpaResult Microsoft/Windows/RemoteAccessServer > $env:USERPROFILE\Desktop\Bpa-RemoteAccessServer.txt
Get-WebApplicationProxyApplication > $env:USERPROFILE\Desktop\WapApp.txt
Get-WebApplicationProxyConfiguration | fl * > $env:USERPROFILE\Desktop\WapConfig.txt
Get-WebApplicationProxyHealth > $env:USERPROFILE\Desktop\WapHealth.txt
Get-WebApplicationProxyAvailableADFSRelyingParty | fl * > $env:USERPROFILE\Desktop\WapAdfsParty.txt
Get-WebApplicationProxySslCertificate | fl * > $env:USERPROFILE\Desktop\WapSslCerts.txt
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\AppProxy > $env:USERPROFILE\Desktop\WapReg.txt
