# ADRecon.ps1
iex (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1")
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
Get-NetConnectionProfile | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-NetConnectionProfile.csv
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
# TODOs
##https://github.com/bayko/365-Secure-Score-Powershell/blob/master/SecureScore.ps1
##https://blog.ciaops.com/2019/10/04/capturing-all-microsoft-secure-score-items/
##https://gallery.technet.microsoft.com/Office-365-Secure-Score-8a81f6af
##https://justaucguy.wordpress.com/2018/01/10/office-365-secure-score-practical-in-depth-analysis/
##https://gist.github.com/psignoret/41793f8c6211d2df5051d77ca3728c09
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

<# SPO #>
$orgName="<name of your Office 365 organization, example: contosotoycompany>"
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Import-Module Microsoft.Online.SharePoint.PowerShell
Connect-SPOService -Url https://$orgName-admin.sharepoint.com
Get-SPOAppInfo -Name " " | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-AppInfo.csv
Get-SPOBrowserIdleSignOut | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-BrowserIdle.csv
Get-SPOBuiltInDesignPackageVisibility | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-DesignPackVis.csv
Get-SPOSite | %{ Get-SPODataEncryptionPolicy -Identity $_.Url } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-DataEncrypt.csv
Get-SPODeletedSite | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-DeletedSites.csv
Get-SPOExternalUser | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-ExternalUser.csv
Get-SPOGeoStorageQuota | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-GeoStorageQuota.csv
Get-SPOHideDefaultThemes | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-HideDefaultThemes.csv
Get-SPOHomeSite | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-HomeSite.csv
Get-SPOHubSite | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-HubSite.csv
Get-SPOKnowledgeHubSite | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-KnowledgeHubSite.csv
Get-SPOMigrationJobStatus | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-MigJobStatus.csv
Get-SPOMultiGeoCompanyAllowedDataLocation | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-MGeoCompany.csv
Get-SPOOrgAssetsLibrary | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-OrgAssesstsLib.csv
Get-SPOOrgNewsSite | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-OrgNewsSite.csv
Get-SPOSite | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-Sites.csv
Get-SPOSite | %{ Get-SPOSiteCollectionAppCatalogs -Site $_.Url } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SiteCollectionAppCat.csv
Get-SPOSite | %{ Get-SPOSiteDataEncryptionPolicy -Identity $_.Url } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SiteDataEncryptPolicy.csv
Get-SPOSiteDesign | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SiteDesign.csv
Get-SPOSiteDesign | %{ Get-SPOSiteDesignRights $_ } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SiteDesignRights.csv
Get-SPOSiteDesignTask | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SiteDesignTask.csv
Get-SPOSite | %{ Get-SPOSiteGroup $_ | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SiteGroup-$($_.Title).csv }
Get-SPOTenant | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-Tenant.csv
Get-SPOTenantLogEntry | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-TenantLogEntry.csv
Get-SPOTenantLogLastAvailableTimeInUtc | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-LastLog.csv
Get-SPOTenantServicePrincipalPermissionGrants | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-PermGrant.csv
Get-SPOTenantServicePrincipalPermissionRequests | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-PermReq.csv
Get-SPOTenantSyncClientRestriction | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-SyncClientRestriction.csv
Get-SPOTheme | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-Theme.csv
Get-SPOSite | %{ Get-SPOUser $_ | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-User-$($_.Title).csv }
Get-SPOWebTemplate | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SPO-WebTemplate.csv
Disconnect-SPOService

<# EXO #>
$creds = Get-Credential
$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $creds -Authentication Basic -AllowRedirection
Import-PSSession $session -DisableNameChecking
$Mailboxes = Get-Mailbox -ResultSize Unlimited
Get-AcceptedDomain | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AcceptedDomains.csv
Get-AccessToCustomerDataRequest | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AccessToCustomer.csv
Get-ActiveSyncDeviceAccessRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ActiveSyncDeviceAccessRule.csv
Get-ActiveSyncDeviceClass | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ActiveSyncDeviceClass.csv
Get-ActiveSyncOrganizationSettings | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ActiveSyncOrgSettings.csv
Get-AddressBookPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AddressBookPolicy.csv
Get-AdminAuditLogConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AdminAuditLogConfig.csv
Get-AdministrativeUnit | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AdministrativeUnit.csv
Get-AdvancedThreatProtectionDocumentDetail | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ATPDocumentDetail.csv
Get-AdvancedThreatProtectionDocumentReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ATPDocumentReport.csv
Get-AdvancedThreatProtectionTrafficReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ATPTrafficReport.csv
Get-AntiPhishPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AntiPhishPolicy.csv
Get-AntiPhishRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AntiPhishRule.csv
Get-App | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Apps.csv
Get-ApplicationAccessPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AppAccessPolicy.csv
Get-ATPEvaluation | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ATPEval.csv
Get-AtpPolicyForO365 | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ATPPolicy.csv
Get-ATPTotalTrafficReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ATPTotalTrafficReport.csv
Get-AuditConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AuditConfig.csv
Get-AuditConfigurationPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AuditConfigPolicy.csv
Get-AuditConfigurationRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AuditConfigRule.csv
Get-AuditLogSearch | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AuditLogSearch.csv
Get-AuthenticationPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AuthNPolicy.csv
Get-AuthServer | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AuthServer.csv
Get-AvailabilityAddressSpace | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AvailAddressSpace.csv
Get-AvailabilityConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-AvailConfig.csv
Get-BlockedSenderAddress | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-BlockedSenderAddress.csv
Get-CASMailbox | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-CASMB.csv
Get-CASMailboxPlan | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-CASMBPlan.csv
Get-ClassificationRuleCollection | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ClassRuleCollection.csv
Get-ClientAccessRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ClientAccessRule.csv
$Mailboxes | %{ Get-Clutter -Identity $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Clutter.csv
Get-CompliancePolicyFileSyncNotification | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-CompliancePolicyFileSyncNotification.csv
Get-CompliancePolicySyncNotification | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-CompliancePolicySyncNotification.csv
Get-ComplianceTag | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ComplianceTag.csv
Get-ComplianceTagStorage | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ComplianceTagStorage.csv
Get-Contact | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Contact.csv
Get-DataClassification | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DataClass.csv
Get-DataClassificationConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DataClassConfig.csv
Get-DataEncryptionPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DataEncryptPolicy.csv
Get-DataRetentionReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DataRetentionReport.csv
Get-DeviceComplianceDetailsReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceCompDetailsReport.csv
Get-DeviceComplianceDetailsReportFilter | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceCompDetailsReportFilter.csv
Get-DeviceCompliancePolicyInventory | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceCompPolicyInven.csv
Get-DeviceComplianceSummaryReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceCompSummary.csv
Get-DeviceComplianceUserInventory | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceCompUserInventory.csv
Get-DeviceConditionalAccessPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceConditionalAccessPolicy.csv
Get-DeviceConditionalAccessRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceConditionalAccessRule.csv
Get-DeviceConfigurationPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceConfigPolicy.csv
Get-DeviceConfigurationRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceConfigRule.csv
Get-DevicePolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DevicePolicy.csv
Get-DeviceTenantPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceTenantPolicy.csv
Get-DeviceTenantRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DeviceTenantRule.csv
Get-DistributionGroup | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DistGroup.csv
Get-DkimSigningConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DkimSignConfig.csv
Get-DlpDetailReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DlpDetailReport.csv
Get-DlpDetectionsReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DlpDetectionsReport.csv
Get-DlpIncidentDetailReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DlpIncidentDetailReport.csv
Get-DlpPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DlpPolicy.csv
Get-DlpPolicyTemplate | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DlpPolicyTemplate.csv
Get-DlpSiDetectionsReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DlpSiDetectReport.csv
Get-DynamicDistributionGroup | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-DynDistGroup.csv
Get-ElevatedAccessApprovalPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ElevateAccessApprovalPolicy.csv
Get-ElevatedAccessAuthorization | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ElevateAccessAuthZ.csv
Get-ElevatedAccessRequest | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ElevateAccessRequest.csv
Get-EligibleDistributionGroupForMigration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-EligibleDistGroup.csv
Get-EmailAddressPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-EmailAddressPolicy.csv
Get-EvaluationModeReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-EvalModeReport.csv
Get-FederatedOrganizationIdentifier | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-FedOrgId.csv
Get-AcceptedDomain | %{ Get-FederationInformation $_.DomainName } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-FedInfo.csv
Get-FederationTrust | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-FedTrust.csv
Get-FfoMigrationReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-FfoMigReport.csv
$Mailboxes | %{ Get-FocusedInbox -Identity $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-FocusedInbox.csv
Get-Group | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Group.csv
Get-GroupMailbox | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-GroupMB.csv
Get-HistoricalSearch | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HistSearch.csv
Get-HostedConnectionFilterPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HostedConnFilterPolicy.csv
Get-HostedContentFilterPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HostedContentFilterPolicy.csv
Get-HostedContentFilterRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HostedContentFilterRule.csv
Get-HostedOutboundSpamFilterPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HostedOutSpamFilterPolicy.csv
Get-HostedOutboundSpamFilterRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HostedOutSpamFilterRule.csv
Get-HybridMailflow | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HybridMail.csv
Get-HybridMailflowDatacenterIPs | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-HybridMailDatacenter.csv
Get-InboundConnector | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-InboundConnector
$Mailboxes | %{ Get-InboxRule -Mailbox $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-InboxRules.csv
Get-IntraOrganizationConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-IntraOrgConfig.csv
Get-IntraOrganizationConnector | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-IntraOrgConn.csv
Get-IRMConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-IrmConfig.csv
Get-JournalRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-JournalRule.csv
Get-LinkedUser | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-LinkedUser.csv
$Mailboxes | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Mailbox.csv
Get-MailboxAuditBypassAssociation | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBAuditBypass.csv
$Mailboxes | %{ Get-MailboxMessageConfiguration -Identity $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBMessageConfig.csv
$Mailboxes | %{ Get-MailboxOverrideConfiguration -Identity $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBOverrideConfig.csv
$Mailboxes | %{ Get-MailboxPermission -Identity $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBPermissions.csv
Get-MailboxPlan | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBPlan.csv
Get-MailboxSearch | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBSearch.csv
$Mailboxes | %{ Get-MailboxStatistics -Identity $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MBStats.csv
Get-MailContact | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailContact.csv
Get-MailDetailATPReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailATPReport.csv
Get-MailDetailDlpPolicyReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailDlpPolicyReport.csv
Get-MailDetailEvaluationModeReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailEvalModeReport.csv
Get-MailDetailMalwareReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailMalwareReprot.csv
Get-MailDetailReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailReport.csv
Get-MailDetailSpamReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailSpamReport.csv
Get-MailDetailTransportRuleReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailDetailTransportRuleReport.csv
Get-MailFilterListReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailFilterListReport.csv
Get-MailFlowStatusReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailFlowStatusReport.csv
Get-MailPublicFolder | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailPubFolder.csv
Get-MailTrafficATPReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailTrafficAtpReport.csv
Get-MailTrafficPolicyReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailTrafficPolicyReport.csv
Get-MailTrafficReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailTrafficReport.csv
Get-MailTrafficTopReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailTrafficTopReport.csv
Get-MailUser | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MailUser.csv
Get-MalwareFilterPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MalwareFilterPolicy.csv
Get-MalwareFilterRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MalwareFilterRule.csv
Get-ManagementRole | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MgmtRole.csv
Get-ManagementRoleAssignment | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MgmtRoleAssign.csv
Get-ManagementScope | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MgmtScope.csv
Get-MessageClassification | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MessageClass.csv
Get-MessageTrace | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MessageTrace.csv
Get-MigrationBatch | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MigBatch.csv
Get-MigrationConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MigConfig.csv
Get-MigrationEndpoint | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MigEndpoint.csv
Get-MigrationStatistics | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MigStatistics.csv
Get-MigrationUser | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MigUser.csv
Get-MobileDevice | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MobileDevice.csv
Get-MobileDeviceMailboxPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MobileDeviceMBPolicy.csv
Get-MoveRequest | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MoveRequest.csv
Get-AcceptedDomain | %{ Get-MxRecordReport -Domain $_.DomainName } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-MXRecordReport.csv
Get-Notification | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Notification.csv
Get-OMEConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OMEConfig.csv
Get-OnPremisesOrganization | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OnPremOrg.csv
Get-OrganizationalUnit | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OrgUnit.csv
Get-OrganizationConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OrgConfig.csv
Get-OrganizationRelationship | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OrgRelation.csv
Get-OutboundConnector | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OutboundConn.csv
Get-AcceptedDomain | %{ Get-OutboundConnectorReport -Domain $_.DomainName } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OutboundConnReport.csv
Get-OutlookProtectionRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OutlookProtRule.csv
Get-OwaMailboxPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-OwaMbPolicy.csv
Get-PartnerApplication | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-PartnerApp.csv
Get-PerimeterConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-PerimeterConfig.csv
Get-PhishFilterPolicy -Detailed -SpoofAllowBlockList | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-PhishFilterPolicy.csv
Get-PolicyTipConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-PolicyTipConfig.csv
Get-PublicFolder | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-PubFolder.csv
Get-PublicFolderStatistics | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-PubFolderStats.csv
Get-QuarantineMessage -StartReceivedDate (Get-Date).AddDays(-90) -EndReceivedDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-QuarentineMessage.csv
Get-RbacDiagnosticInfo | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RbacDiagInfo.csv
Get-Recipient | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-Recipient.csv
Get-RecipientPermission | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RecipientPerm.csv
Get-RemoteDomain | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RemoteDomain.csv
Get-ReportExecutionInstance | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ReportExecInstance.csv
Get-ReportScheduleList | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ReportScheduleList.csv
Get-ReportScheduleList | %{ Get-ReportSchedule $_ } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ReportSchedule.csv
Get-ReportSubmissionPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ReportSubmissionPolicy.csv
Get-ResourceConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ResourceConfig.csv
Get-RetentionEvent | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RetentionEvent.csv
Get-RetentionPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RetentionPolicy.csv
Get-RetentionPolicyTag | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RetentionPolicyTag.csv
Get-RMSTemplate | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RmsTemplate.csv
Get-RoleAssignmentPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RoleAssignPolicy.csv
Get-RoleGroup | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-RoleGroup.csv
Get-RoleGroup | %{ Get-RoleGroupMember $_.Name | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-$(($_.Name).Replace(' ',''))-RoleGroupMember.csv}
Get-SafeAttachmentPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SafeAttachPolicy.csv
Get-SafeAttachmentRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SafeAttachRule.csv
Get-SafeLinksPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SafeLinkPolicy.csv
Get-SafeLinksRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SafeLinkRule.csv
Get-SCInsights | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-ScInsights.csv
Get-SearchDocumentFormat | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SearchDocFormat.csv
Get-SecurityPrincipal | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SecPrincipal.csv
Get-SensitivityLabelActivityDetailsReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SensitiveLabelActDetailReport.csv
Get-SensitivityLabelActivityReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SensitiveLabelActReport.csv
Get-SharingPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SharingPolicy.csv
Get-SiteMailbox | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SiteMailbox.csv
Get-SiteMailboxProvisioningPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SiteMbProvPolicy.csv
Get-SmimeConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SmimeConfig.csv
Get-SpoofMailReport -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SpoofMailReport.csv
Get-SupervisoryReviewPolicyV2 -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SupervisoryReviewPolicyv2.csv
Get-SupervisoryReviewRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SuperReviewRule.csv
$Mailboxes | %{ Get-SweepRule -Mailbox $_.Name } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SweepRule.csv
Get-SyncConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SyncConfig.csv
Get-SyncRequest | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-SyncRequest.csv
Get-TransportConfig | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-TransportConfig.csv
Get-TransportRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-TransportRule.csv
Get-TransportRuleAction | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-TransportRuleAction.csv
Get-TransportRulePredicate | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-TransportRulePred.csv
Get-UnifiedGroup | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-UnifiedGroup.csv
Get-User | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-User.csv
Test-IRMConfiguration | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\EXO-TestIrmConfig.csv
Remove-PSSession $session

<# Sec & Comp Center #>
$creds = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $creds -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
Get-ActivityAlert | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-ActivityAlert.csv
Get-ComplianceCase | %{ Get-CaseHoldPolicy } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CaseHoldPolicy.csv
Get-CaseHoldRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CaseHoldRule.csv
Get-ComplianceCase | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompCase.csv
Get-ComplianceCase | %{ Get-ComplianceCaseMember } | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompCaseMember.csv
Get-ComplianceCaseStatistics | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompCaseStats.csv
Get-ComplianceRetentionEvent | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompRetentionEvent.csv
Get-ComplianceRetentionEventType | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompRetentionEventType.csv
Get-ComplianceSearch | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompSearch.csv
Get-ComplianceSearchAction | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompSearchAction.csv
Get-ComplianceSecurityFilter | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-CompSecurityFeature.csv
Get-DlpCompliancePolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-DlpCompPolicy.csv
Get-DlpComplianceRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-DlpCompRule.csv
Get-DlpEdmSchema | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-DlpEdmSchema.csv
Get-DlpSensitiveInformationType | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-DlpSensitiveInfoType.csv
Get-eDiscoveryCaseAdmin | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-eDiscCaseAdmin.csv
Get-FilePlanPropertyAuthority | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanAuth.csv
Get-FilePlanPropertyCategory | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanCat.csv
Get-FilePlanPropertyCitation | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanCit.csv
Get-FilePlanPropertyDepartment | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanDept.csv
Get-FilePlanPropertyReferenceId | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanRef.csv
Get-FilePlanPropertyStructure | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanStruct.csv
Get-FilePlanPropertySubCategory | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-FilePlanSubCat.csv
Get-HoldCompliancePolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-HoldCompPolicy.csv
Get-HoldComplianceRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-HoldCompRule.csv
Get-InformationBarrierPoliciesApplicationStatus | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-InfoBarrierPolicyAppStatus.csv
Get-InformationBarrierPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-InfoBarrierPolicy.csv
Get-Label | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-Label.csv
Get-LabelPolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-LabelPolicy.csv
Get-LabelPolicyRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-LabelPolicyRule.csv
Get-OrganizationSegment | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-OrgSegment.csv
Get-ProtectionAlert | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-ProtAlert.csv
Get-RetentionCompliancePolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-RetenCompPolicy.csv
Get-RetentionComplianceRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-RetenCompRule.csv
Get-SupervisoryReviewOverallProgressReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-SuperReviewOverProgressReport.csv
Get-SupervisoryReviewTopCasesReport | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-SuperReviewTopCaseReport.csv
Get-TeamsRetentionCompliancePolicy | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-TeamsRetenCompPolicy.csv
Get-TeamsRetentionComplianceRule | New-FlatObject | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\SCC-TeamsRetenCompRule.csv
Remove-PSSession $Session

<# AAD Connect #>
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1'
#ADSyncTools.psm1
#ADConnectivityTools.psm1
Import-Module ADSync
New-AzureADSSOAuthenticationContext
Get-AzureADSSOStatus | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SSO-Status.csv
Get-AzureADSSOComputerAcccountInformation | Export-Csv $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-SSO-ComputerAccount.csv
Get-ADSyncServerConfiguration -Path $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:COMPUTERNAME-AADC-ServerConfig.csv
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
