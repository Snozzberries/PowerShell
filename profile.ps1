$gitHub = "https://github.com/Snozzberries/PowerShell/blob/master/profile.ps1"
$profileVersion = "0.2"

$vimPath = "${env:ProgramFiles(x86)}\Vim\vim80\vim.exe"
$gitPath = "$env:ProgramFiles\Git\bin\git.exe"

Set-Alias vi $vimPath
Set-Alias vim $vimPath
Set-Alias git $gitPath

$host.UI.RawUI.BackgroundColor = "black"
Clear-Host

function Set-Prompt
{
    PARAM
    (
        [Parameter()][ValidateSet("reset","simple")]$prompt
    )
    switch($prompt)
    {
        "simple"
        {
            function global:Prompt
            {
                "PS> "
            }
        }
        "reset"
        {
            function global:Prompt
            {
                $(if (test-path variable:/PSDebugContext) { '[DBG]: ' } else { '' }) + 'PS ' + $(Get-Location) + $(if ($nestedpromptlevel -ge 1) { '>>' }) + '> '
            }
        }
        default
        {
            function global:Prompt
            {
                Write-Host -NoNewLine "PS"
                Write-Host -NoNewLine "[$(((Get-History -Count 1).Id + 1).ToString('0000'))]" -ForegroundColor "green"
                Write-Host -NoNewLine "[$env:USERNAME@$env:USERDNSDOMAIN]" -ForegroundColor "red"
                Write-Host -NoNewLine "[$(Get-Location)]" -ForegroundColor "yellow"
                '> '
            }
        }
    }
}
Write-Host "`r"
Write-Host "$env:COMPUTERNAME.$((Get-WmiObject Win32_ComputerSystem).Domain)"
Get-NetIPAddress|?{$_.addressState -eq "Preferred" -and $_.suffixOrigin -ne "WellKnown"}|%{$if=$_;"$((Get-NetAdapter -InterfaceIndex $_.ifIndex).Name) - $($_.ipAddress) /$($_.prefixLength) => $(if($_.addressFamily -eq "IPv4"){(Get-NetRoute|?{$_.ifIndex -eq $if.ifIndex -and $_.addressFamily -ne "IPv6" -and $_.NextHop -ne "0.0.0.0"}).NextHop}else{(Get-NetRoute|?{$_.ifIndex -eq $if.ifIndex -and $_.addressFamily -ne "IPv4" -and $_.NextHop -ne "::"}).NextHop})`n`tDNS Servers $((Get-DnsClientServerAddress|?{$_.interfaceIndex -eq $if.ifIndex -and $_.addressFamily -eq $if.addressFamily}).ServerAddresses|%{"- $_"})`n`t$(Get-NetConnectionProfile|?{$_.interfaceIndex -eq $if.interfaceIndex}|%{if($_.NetworkCategory -eq "DomainAuthenticated"){$profile="Domain"}else{$profile=$_.NetworkCategory}"Firewall: $profile - $(if((Get-NetFirewallProfile $profile).Enabled){'Enabled'}else{'Disabled'})"})"}
Write-Host "`r"
Set-Prompt

# Open VIM to profile
function Edit-Profile
{
    vim "$env:UserProfile\Documents\WindowsPowerShell\profile.ps1"
}

# Open VIM to VIM Settings
function Edit-Vimrc
{
    vim $env:UserProfile\_vimrc
}

function Invoke-GitPush
{
    PARAM (
        [Parameter()][string]$target = ".\",
        [Parameter(Mandatory=$true)] $comment
    )
    PROCESS
    {
        git add $target
        git commit -m $comment
        git push -u origin master
    }
}

function Test-Profile
{
    
}
