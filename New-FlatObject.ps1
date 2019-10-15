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
            if ($prop.Value -is [array])
            {
                $counter = 0
                foreach ($value in $prop.Value)
                {
                    if ($value -is [array]) { New-FlatObject -object $value }
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
