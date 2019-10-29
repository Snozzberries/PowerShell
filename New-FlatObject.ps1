function New-FlatObject
{
    Param 
    (
        [Parameter(Mandatory,
            ValueFromPipeline)]
        $object
    )

    process
    {
        $returnHashTable = [ordered]@{ }
        foreach ($prop in $object.psobject.Properties)
        {
            if ($prop.Value -is [array] -or $prop.Value.GetType().Name -Like "List*")
            #if (($prop.Value -ne $null) -and (-not $prop.Value.GetType().isValueType))
            {
                $counter = 0
                foreach ($value in $prop.Value)
                {
                    if ($value -is [array] -or $prop.Value.GetType().Name -Like "List*")
                    #if (($prop.Value -ne $null) -and (-not $prop.Value.GetType().isValueType))
                    { 
                        foreach ($recurse in (New-FlatObject -object $value).psobject.Properties)
                        {
                            $returnHashTable["$($prop.Name)-$($recurse.Name)"] = $recurse.Value
                        }
                    }
                    $returnHashTable["$($prop.Name)-$counter"] = $value
                    $counter++
                }
            }
            else
            {
                $returnHashTable[$prop.Name] = $prop.Value
            }
        }
        return [PSCustomObject]$returnHashTable | sort @{Expression ={ (($_.psobject.properties) | measure).count } } -Descending
    }
}
