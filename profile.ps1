$gitHub = "https://github.com/Snozzberries/PowerShell/blob/master/profile.ps1"
$profileVersion = "0.1"

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
        [Parameter()] $target = ".\",
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
