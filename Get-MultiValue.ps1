function Get-MultiValue
{
    Param 
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $object
    )

    process
    {
        if ($object.Count -gt 1)
        {
            foreach ($o in $object)
            {
                Get-MultiValue -object $o
            }
        }

        $returnObject = New-Object -TypeName psobject
        foreach ($prop in $object.psobject.Properties)
        {
            if ($prop.Value -is [array])
            {
                $counter = 0
                foreach ($value in $prop.Value)
                {
                    if ($value -is [array]) { Get-MultiValue -object $value }
                    $returnObject | Add-Member -MemberType NoteProperty -Name "$($prop.Name)$counter" -Value $value
                    $counter++
                }
            }
            else
            {
                $returnObject | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value
            }
        }
        return $returnObject
    }
}
