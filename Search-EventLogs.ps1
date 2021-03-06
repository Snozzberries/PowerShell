# Search security logs of all domain controlers in the forest for failed login attempts due to bad password for the specified samAccountName and return the source addresses of the login
$user='samAccountName';(Get-ADForest).Domains|%{Get-ADDomainController -Filter * -Server $_}|%{Get-WinEvent -ComputerName $_.HostName -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID='4771')]] and *[EventData[Data[@Name='SubjectUserName'] and (Data='$user')]] and *[EventData[Data[@Name='Status'] and (Data='0x18')]] or *[System[(EventID='4771')]] and *[EventData[Data[@Name='TargetUserName'] and (Data='$user')]] and *[EventData[Data[@Name='Status'] and (Data='0x18')]]</Select></Query></QueryList>" -ErrorAction SilentlyContinue|%{([xml]$_.ToXml()).event.eventData.Data|?{$_.Name -eq 'IpAddress'}}|Select @{Name='IP Address';Expression={$_.'#text'}}}

# Look through security logs of local server for failed login attempts due to bad password for the specified samAccountName and return the source address of the login
$user='samAccountName';Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID='4771')]] and *[EventData[Data[@Name='SubjectUserName'] and (Data='$user')]] and *[EventData[Data[@Name='Status'] and (Data='0x18')]] or *[System[(EventID='4771')]] and *[EventData[Data[@Name='TargetUserName'] and (Data='$user')]] and *[EventData[Data[@Name='Status'] and (Data='0x18')]]</Select></Query></QueryList>" -ErrorAction SilentlyContinue|%{([xml]$_.ToXml()).event.eventData.Data|?{$_.Name -eq 'IpAddress'}}|Select @{Name='IP Address';Expression={$_.'#text'}}

# Raw Event Viewer XML filter
$xml = @"
<QueryList>
<Query Id='0' Path='Security'>
  <Select Path='Security'>
   *[System[(EventID='4771')]]
   and
   *[EventData[Data[@Name='SubjectUserName'] and (Data='samAccountName')]]
   and
   *[EventData[Data[@Name='Status'] and (Data='0x18')]]
   or
   *[System[(EventID='4771')]]
   and
   *[EventData[Data[@Name='TargetUserName'] and (Data='samAccountName')]]
   and
   *[EventData[Data[@Name='Status'] and (Data='0x18')]]
  </Select>
</Query>
</QueryList>
"@
