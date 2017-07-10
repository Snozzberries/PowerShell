$gitHub = "https://github.com/Snozzberries/PowerShell/blob/master/profile.ps1"
$profileVersion = "0.1"

$vimPath = "${env:ProgramFiles(x86)}\Vim\vim80\vim.exe"
$gitPath = "$env:ProgramFiles\Git\bin\git.exe"

Set-Alias vi $vimPath
Set-Alias vim $vimPath
Set-Alias git $gitPath

# Open VIM to profile
function Edit-Profile
{
    vim $profile
}

# Open VIM to VIM Settings
function Edit-Vimrc
{
    vim $env:UserProfile\_vimrc
}

function Invoke-GitPush
{
    PARAM (
        [Parameter()] $target = ".",
        [Parameter()] $comment = $null
    )
    PROCESS
    {
        git add $target
        git commit -m $comment
        git pust - u origin master
    }
}