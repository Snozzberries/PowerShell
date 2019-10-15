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
        $returnHashTable = [ordered]@{}
        foreach ($prop in $object.psobject.Properties)
        {
            if ($prop.Value -is [array]) #(($prop.Value -ne $null) -and (-not $prop.Value.GetType().isValueType))
            {
                $counter = 0
                foreach ($value in $prop.Value)
                {
                    if ($value -is [array])
                    { 
                        foreach ($recurse in (New-FlatObject -object $value).psobject.Properties)
                        {
                            $returnHashTable[$recurse.Name] = $recurse.Value
                        }
                    }
                    $returnHashTable["$($prop.Name)$counter"] = $value
                    $counter++
                }
            }
            else
            {
                $returnHashTable[$prop.Name] = $prop.Value
            }
        }
        return [PSCustomObject]$returnHashTable|sort @{Expression={(($_.psobject.properties)|measure).count}} -Descending
    }
}
