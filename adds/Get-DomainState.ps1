New-Item -Type Directory "$env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN)"
Get-ADDomain|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-addomain.json
Get-ADForest|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adforest.json
Get-ADComputer -Filter * -Properties createTimeStamp, distinguishedName, enabled, isCriticalSystemObject, lastLogonDate, managedBy, modified, operatingSystem, passwordExpired, passwordLastSet, PasswordNeverExpires, PasswordNotRequired, primaryGroupId, SIDHistory, TrustedForDelegation, TrustedToAuthForDelegation|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adcomputer.json
Get-ADUser -Filter * -Properties adminCount, CannotChangePassword, createTimeStamp, DistinguishedName, Enabled, isCriticalSystemObject, LastBadPasswordAttempt, LastLogonDate, LockedOut, logonHours, LogonWorkstations, managedBy, modifyTimeStamp, PasswordExpired, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, SIDHistory|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-aduser.json
Get-ADGroup -Filter * -Properties adminCount, createTimeStamp, DistinguishedName, GroupCategory, GroupScope, isCriticalSystemObject, ManagedBy, modifyTimeStamp, SIDHistory|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adgroup.json
Get-ADServiceAccount -Filter *|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adserviceaccount.json
Get-ADDomainController -Filter *|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-addomaincontroller.json
Get-ADObject -Properties * -LDAPFilter "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adobjectdomaincontroller.json
Get-ADReplicationSite|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adreplicationsite.json
Get-ADRootDSE|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adrootdse.json
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Properties * -Filter *|ConvertTo-Json|Out-File "$env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN)\get-adschemahistory.json"
Get-ADObject -SearchBase "CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$(((Get-ADRootDSE).defaultNamingContext))" -Filter * -Properties *|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adoptionalfeatures.json
Get-ADObject -LDAPFilter "(serviceprincipalname=kadmin/changepw)" -Properties *|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adkrbtgt.json
Get-ADObject -LDAPFilter "(objectClass=nTFRSSubscriber)"|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adfrssubscribers.json
Get-ADObject -LDAPFilter "(objectClass=msDFSR-Subscription)"|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-addfsrsubscribers.json
Get-ADReplicationConnection -Properties * -Filter *|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adreplicationconnection.json
& dfsrmig /getmigrationstate|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\dfsrmig.txt
& repadmin /replsummary|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\repadmin.txt
& repadmin.exe /showbackup|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\repadminShowBackup.txt
Get-ADReplicationSite -Filter * -Properties *|ConvertTo-Json|Out-File "$env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN)\get-adreplicationsite.json"
Get-ADOptionalFeature -Filter * -Properties *|ConvertTo-Json|Out-File "$env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN)\Get-ADOptionalFeature.json"
Get-ADObject -SearchBase "CN=Configuration,$((Get-ADRootDSE).defaultNamingContext)" -Filter * -Properties *|ConvertTo-Json|Out-File $env:HOMEDRIVE$env:HOMEPATH\Desktop\$env:USERDNSDOMAIN\get-adConfiguration.json
Compress-Archive -Path $env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN)\ -DestinationPath $env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN).zip
Remove-Item -Recurse "$env:HOMEDRIVE$env:HOMEPATH\Desktop\$($env:USERDNSDOMAIN)" -Force
