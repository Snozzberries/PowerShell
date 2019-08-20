<#
.SYNOPSIS
Test if file path is longer than 200 charecters, and return a symbolic link in the root if that occurs.

.DESCRIPTION
When working with long file paths, often times utilities such as Robocopy are limited by the MAX_PATH.
Leveraging symbolic links we are able to shorten the file path with a new path reference with a shortned name.
https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#maximum-path-length-limitation
#>
function Test-PathLentgh
{
    Param(
        [System.IO.FileInfo]$path
    )

    $l = $path
    $p = Get-Item -Path $path
    if ($p.Length -gt 200)
    {
        $l = New-Item -ItemType SymbolicLink -Path "$($p.Root)\$($p.BaseName)-SYMLINK" -Target $p
    }
    return $l
}
