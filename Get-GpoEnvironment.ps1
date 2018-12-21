<#
.Synopsis
   Gives you some information about group policy objects in the current domain
.DESCRIPTION
   Assumes you have the appropriate permissions.
   -- Allow a -Path parameter for export
   -- Allow a -Credential parameter
   -- Allow a -Domain parameter
   -- Allow a -Type parameter for export
   -- Verify modules actually get loaded successfully
.EXAMPLE
   Get-GpoEnvironment
.EXAMPLE
   $Results = Get-GpoEnvironment
#>
function Remove-InvalidFileNameChars {
  param(
    [Parameter(Mandatory=$true,
      Position=0,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true)]
    [String]$Name
  )

  $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
  return ($Name -replace $re)
}

function Get-GpoEnvironment
{
    [cmdletbinding()]
    Param()
    Begin
    {
        $Process = $true

        $RequiredModules = @(
            'ActiveDirectory',
            'GroupPolicy'
        )
        
        Write-Verbose "Testing Modules"
        foreach ($Module in $RequiredModules)
        {
            Write-Verbose "Testing if $Module is loaded"
            if (!(Get-Module -Name $Module))
            {
                Write-Verbose "$Module not currently loaded"
                if (Get-Module -ListAvailable -Name $Module)
                {
                    Write-Verbose "$Module installed loading"
                    Import-Module -Name $Module
                }
                else
                {
                    Write-Error "PowerShell was unable to load the $Module module. Exiting..."
                    $Process = $false
                    return $null
                }
            }
        }

        $gPLinks = @()
        $Gpos = @()
        $ActiveGpoIds = @()
        $ActiveGpos = @()
        $InactiveGpos = @()
    }
    Process
    {
        Write-Verbose "Testing if processing should proceed ($Process)"
        if (!($Process)) { return $null }

        Write-Verbose "Collecting domain level GPOs"
        $gPLinks += Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions
        Write-Verbose "Collecting OU level GPOs"
        $gPLinks += Get-ADOrganizationalUnit -Filter * -Properties name, distinguishedName, gPLink, gPOptions
        Write-Verbose "Collecting site level GPOs"
        $gPLinks += Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions

        Write-Verbose "Collecting all GPO objects in ADDS"
        $Gpos = Get-GPO -All

        Write-Verbose "Determining which GPOs are actively linked"
        $ActiveGpoIds = $gPLinks | ? { $_.LinkedGroupPolicyObjects -ne $null } | select -ExpandProperty linkedgrouppolicyobjects | Get-ADObject -Properties displayname | select -Unique displayname, objectguid
        Write-Verbose "Determining which GPOs are not a disabled status and have at least one GPO Apply permission set"
        $ActiveGpos = $Gpos | ? { $_.displayName -in $ActiveGpoIds.displayName -and $_.gpoStatus -ne "AllSettingsDisabled" -and ('GpoApply' -in ($_ | Get-GPPermissions -All).permission) }

        Write-Verbose "Determining which GPOs are disabled status or are not linked to an OU"
        $InactiveGpos = $Gpos | ? { $_.displayName -notin $ActiveGpoIds.displayName -or $_.gpoStatus -eq "AllSettingsDisabled" }

        Write-Verbose "Verifying export file path"
        if (!(Test-Path ("$env:USERPROFILE\Desktop\GPO Export\")))
        {
            Write-Verbose "Creating export directory"
            New-Item -ItemType Directory -Path "$env:USERPROFILE\Desktop\GPO Export\" | Out-Null
        }

        Write-Verbose "Exporting the active GPOs"
        $ActiveGpos | % { Get-GPOReport -Name $_.displayName -ReportType Html -Path ("$env:USERPROFILE\Desktop\GPO Export\" + (Remove-InvalidFileNameChars $_.displayName) + ".html") }
        Write-Host "Active GPOs have been exported to your desktop for review."
    }
    End
    {
        Write-Verbose "Testing if processing should proceed ($Process)"
        if (!($Process)) { return $null }

        Write-Verbose "Building result object"
        $ResultObject = New-Object PSObject -Property @{
            ActiveGpoCount   = $ActiveGpos.Count
            ActiveGpoNames   = ($ActiveGpos.displayName | sort)
            InactiveGpoCount = $InactiveGpos.Count
            InactiveGpoNames = ($InactiveGpos.displayName | sort)
            TotalGpoCount    = $Gpos.Count
        }

        Write-Verbose "Returning the result object to the calling pipeline"
        return $ResultObject
    }
}
