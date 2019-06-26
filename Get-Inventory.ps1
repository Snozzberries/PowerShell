# ADRecon.ps1
# https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1
# AAD Connect MA Documenter
# https://github.com/Microsoft/AADConnectConfigDocumenter

# Azure Only
Invoke-RestMethod -Headers @{"Metadata"="true"} -URI http://169.254.169.254/metadata/instance?api-version=2017-08-01 -Method get -OutFile $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Metadata.json

<# Windows #>
gwmi Win32_OperatingSystem|select Caption,BuildNumber,InstallDate,Locale,MUILanguages,OSArchitecture,OSLanguage,SystemDrive,Version|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-OperatingSystem.csv
gwmi Win32_ComputerSystem|Select Name,DNSHostName,BootupState,PartOfDomain,Domain,DomainRole,NumberOfProcessors,NumberOfLogicalProcessors,TotalPhysicalMemory|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-ComputerSystem.csv

gwmi Win32_Product|select Vendor,Name,Version,Caption|Export-Csv -Path $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Software.csv
# Does not work in Windows, only Windows Server, use DISM on Windows OS
Get-WindowsFeature|?{$_.InstallState -eq "Installed"}|Select DisplayName,Name|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Features.csv
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates|Select LastDeploymentChangeTime,Title,Description,IsBeta,IsDownloaded,SupportUrl|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-AvailableUpdates.csv
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().QueryHistory(0,(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().GetTotalHistoryCount())|Select Date,Title,Description,HResult,ResultCode,SupportURL|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-UpdateHistory.csv

wevtutil.exe epl Application $env:HOMEPATH\Desktop\$env:COMPUTERNAME-ApplicationLog.evtx /q:"*[System[(Level=1 or Level=2 or Level=3)]]"
wevtutil.exe epl System $env:HOMEPATH\Desktop\$env:COMPUTERNAME-SystemLog.evtx /q:"*[System[(Level=1 or Level=2 or Level=3)]]"

Get-NetFirewallProfile|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-NetFirewallProfile.csv
gwmi Win32_Service|select SystemName,DisplayName,Name,Caption,Description,Status,State,PathName,StartMode,StartName|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Services.csv

get-smbshare|select Name,ShareState,Description,Path,AvailabilityType,FolderEnumerationMode,CachingMode,CurrentUsers,SecurityDescriptor|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Shares.csv

Get-NetAdapter|select Name,ifDesc,SystemName,LinkSpeed,MediaType,MacAddress,Status,AdminStatus,ifOperStatus,MediaConnectionState,PhysicalMediaType,DriverFileName,DriverInformation,DriverVersion,ifIndex|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Adapters.csv
Get-NetIPAddress|Select InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,Type,AddressFamily,AddressState,IPv4Address,IPv6Address|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Addresses.csv
Get-NetIPInterface|select ifIndex,ifAlias,RouterDiscovery,Dhcp,ConnectionState|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-DhcpState.csv
Get-NetTCPConnection|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-NetTcpConnection.csv
"InterfaceAlias,InterfaceIndex,ServerAddress"> $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Dns.csv;Get-DnsClientServerAddress|%{foreach($i in $_.ServerAddresses){"$($_.InterfaceAlias),$($_.InterfaceIndex),$i">> $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Dns.csv}}

Get-ScheduledTask|select TaskName,TaskPath,State,Actions,Author,Date,Description,Documentation,Principal,SecurityDescriptor,URI|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Tasks.csv

gwmi Win32_UserAccount -Filter "LocalAccount='True'"|select Name,Status,PasswordExpires,Disabled,Lockout,PasswordRequired,SID|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-LocalUsers.csv
gwmi Win32_Group -Filter "LocalAccount='True'"|select Name,Status,Caption,Description,SID|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-LocalGroups.csv
if($PSVersionTable.PSVersion.Major -gt 4)
{
    Get-LocalGroup|%{Get-LocalGroupMember -Name $_|Select Name,SID,PrincipalSource|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Members-$_.csv}
}
else
{
    gwmi Win32_Group -Filter "LocalAccount='True'"|%{($_.GetRelated("Win32_UserAccount")|Select Name,SID,Domain,Disabled,Status,Caption,LocalAccount)|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Members-$($_.Name).csv}
}

w32tm /query /status > $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Time.txt

Get-BpaModel | %{$_.id; Invoke-BpaModel -ModelId $_.id; Get-BpaResult -ModelId $_.id|Export-CSV $env:HOMEPATH\Desktop\$env:COMPUTERNAME-BPA-$($_.Id.Substring($_.Id.LastIndexOf('/')+1)).csv}

# Requires Elevation:
if((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Get-Disk|Select DiskNumber,PartitionStyle,ProvisioningType,OperationalStatus,HealthStatus,BusType,BootFromDisk,IsBoot,IsClustered,IsSystem,Location,Manufacturer,Model,NumberOfPartitions,SerialNumber,Path,Size,PhysicalSectorSize,LogicalSectorSize,LargestFreeExtent|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Disks.csv
    Get-Partition|Select DiskPath,Type,OperationalStatus,DiskNumber,DriveLetter,IsActive,IsBoot,IsHidden,IsOffline,IsReadOnly,IsSystem,NoDefaultDriveLetter,Offset,PartitionNumber,Size|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Partitions.csv
    Get-Volume|select FileSystemLabel,DriveLetter,FileSystem,OperationalStatus,HealthStatus,DriveType,DedupMode,AllocationUnitSize,Size,SizeRemaining|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Volumes.csv

    (Get-WinEvent -ListLog *)|Select *|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-ListLog.csv
    wevtutil.exe epl Security $env:HOMEPATH\Desktop\$env:COMPUTERNAME-SecLog90Day.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= $((New-TimeSpan -End (Get-Date) -Start (Get-Date).AddDays(-90)).TotalMilliseconds)]]]"

    Get-Process|select Name,ProcessName,Id,Path,Company,Description,Product,StartTime|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Processes.csv

    if($PSVersionTable.PSVersion.Major -gt 4)
    {
        Get-GPResultantSetOfPolicy -ReportType Html -Path $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.html;Get-GPResultantSetOfPolicy -ReportType Xml -Path $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.xml
    }
    else
    {
        gpresult.exe /h $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.html;gpresult.exe /x $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.xml
    }
}
else
{
    $script = {
        Get-Disk|Select DiskNumber,PartitionStyle,ProvisioningType,OperationalStatus,HealthStatus,BusType,BootFromDisk,IsBoot,IsClustered,IsSystem,Location,Manufacturer,Model,NumberOfPartitions,SerialNumber,Path,Size,PhysicalSectorSize,LogicalSectorSize,LargestFreeExtent|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Disks.csv
        Get-Partition|Select DiskPath,Type,OperationalStatus,DiskNumber,DriveLetter,IsActive,IsBoot,IsHidden,IsOffline,IsReadOnly,IsSystem,NoDefaultDriveLetter,Offset,PartitionNumber,Size|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Partitions.csv
        Get-Volume|select FileSystemLabel,DriveLetter,FileSystem,OperationalStatus,HealthStatus,DriveType,DedupMode,AllocationUnitSize,Size,SizeRemaining|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Volumes.csv

        (Get-WinEvent -ListLog *)|Select *|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-ListLog.csv
        wevtutil.exe epl Security $env:HOMEPATH\Desktop\$env:COMPUTERNAME-SecLog90Day.evtx /q:"""*[System[TimeCreated[timediff(@SystemTime) <= $((New-TimeSpan -End (Get-Date) -Start (Get-Date).AddDays(-90)).TotalMilliseconds)]]]"""

        Get-Process|select Name,ProcessName,Id,Path,Company,Description,Product,StartTime|Export-Csv $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Processes.csv

        if($PSVersionTable.PSVersion.Major -gt 4)
        {
            Get-GPResultantSetOfPolicy -ReportType Html -Path $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.html;Get-GPResultantSetOfPolicy -ReportType Xml -Path $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.xml
        }
        else
        {
            gpresult.exe /h $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.html;gpresult.exe /x $env:HOMEPATH\Desktop\$env:COMPUTERNAME-Rsop.xml
        }
    }
    Start-Process powershell -Verb runAs -ArgumentList "-Command",$script -wait
}

<# O365 #>
Import-Module Az
Import-Module MSOnline
Connect-AzAccount
Connect-MsolService
Get-MsolDomain
Get-MsolDomain|?{$_.authentication -eq "Federated"}
Get-MsolDomain|?{$_.authentication -eq "Federated"}|select name
Get-MsolDomain|?{$_.authentication -eq "Federated"}|%{$_.name;Get-MsolDomainFederationSettings -DomainName $_.name|fl *}
Get-MsolAccountSku|ft skupartnumber,activeunits
(Get-AzureADTenantDetail).verifieddomains|select name,capabilities|Group-Object capabilities|%{$_.group|sort capabilities}
Get-AzureADDirectoryRole|%{"";$_.displayname;Get-AzureADDirectoryRoleMember -ObjectId  $_.objectid|ft}
Get-MsolRole|%{"";$_.name;Get-MsolRoleMember -RoleObjectId $_.objectid|ft}
$o=Get-AzureADDirectoryRole|%{Get-AzureADDirectoryRoleMember -ObjectId $_.objectid|select objectid,displayname}
$o+=get-msolrole|%{Get-MsolRoleMember -RoleObjectId $_.objectid|select objectid,displayname}
$o=$o|select objectid,displayname -unique
$o|%{Get-MsolUser -ObjectId $_.objectid | select DisplayName,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationRequirements.State -ne $null){ $_.StrongAuthenticationRequirements.State} else { "Disabled"}}}}
$x=$o|%{Get-MsolUser -ObjectId $_.objectid | select DisplayName,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationRequirements.State -ne $null){$_.StrongAuthenticationRequirements.State} else { "Disabled"}}}}
$x|group 'MFA Status'
$x=Get-AzureADDevice|select objectid,displayname,accountenabled,deviceostype,deviceosversion,profiletype,approximatelastlogontimestamp
$x|group profiletype,deviceostype
Get-MsolCompanyInformation

<# WAP #>
gc C:\Windows\System32\drivers\etc\hosts > $env:USERPROFILE\Desktop\hosts.txt
gci Cert:\LocalMachine\my|fl * > $env:USERPROFILE\Desktop\LocalMachineCerts.txt
Invoke-BpaModel Microsoft/Windows/RemoteAccessServer
Get-BpaResult Microsoft/Windows/RemoteAccessServer > $env:USERPROFILE\Desktop\Bpa-RemoteAccessServer.txt
Get-WebApplicationProxyApplication > $env:USERPROFILE\Desktop\WapApp.txt
Get-WebApplicationProxyConfiguration | fl * > $env:USERPROFILE\Desktop\WapConfig.txt
Get-WebApplicationProxyHealth > $env:USERPROFILE\Desktop\WapHealth.txt
Get-WebApplicationProxyAvailableADFSRelyingParty | fl * > $env:USERPROFILE\Desktop\WapAdfsParty.txt
Get-WebApplicationProxySslCertificate | fl * > $env:USERPROFILE\Desktop\WapSslCerts.txt
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\AppProxy > $env:USERPROFILE\Desktop\WapReg.txt

<# AAD Connect #>
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'
New-AzureADSSOAuthenticationContext
$env:COMPUTERNAME;Get-AzureADSSOStatus
Import-Module adsync
$x=Get-ADSyncConnector|?{$_.Type -eq "AD"}
$c=Get-ADSyncConnector|?{$_.Name -like "*AAD"}
$c.Name;Get-ADSyncAADCompanyFeature -ConnectorName $c.Name
Get-ADSyncAADPasswordResetConfiguration -Connector $C.Name
Get-ADSyncGlobalSettings|select -ExpandProperty parameters|ft Name, Value
Get-ADSyncScheduler
Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1'
Get-ADSyncADConnectorAccount
Get-ADUser -Filter 'name -like "svc.ad.adconnect"'|Get-ADPrincipalGroupMembership|select Name
Get-ADUser -Filter "Name -like 'svc.ad.*'" -Properties passwordLastSet|select name,password*

<# ADFS #>
Import-Module Adfs
Get-AdfsGlobalAuthenticationPolicy
$x=Get-AdfsProperties|fl *
$x.WIASupportedUserAgents
Get-AdfsDeviceRegistration
gci Cert:\LocalMachine\My|fl *
Get-AdfsSslCertificate
Get-AdfsCertificate
gci -Recurse HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\
gci -Recurse HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL|Get-ItemProperty|%{$_."(default)";$_.pschildname;"";$_.functions;""}
gci -Recurse HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319
Get-AdfsRelyingPartyTrust
Import-Module Msonline
Connect-MsolService
Get-MsolDomain|?{$_.authentication -eq "Federated"}|%{$_.name;Get-MsolFederationProperty -DomainName $_.name}
Get-AdfsEndpoint|?{$_.enabled -eq "True"}|select Proxy,Protocol,AddressPath,ClientCredentialType| fl
Get-AdfsAdditionalAuthenticationRule
Get-AdfsAuthenticationProvider
Get-AdfsClient
Get-AdfsWebApplicationProxyRelyingPartyTrust
Get-AdfsWebConfig
Get-AdfsWebTheme
