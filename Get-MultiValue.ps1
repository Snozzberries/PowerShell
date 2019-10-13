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
        $returnObject = New-Object -TypeName psobject # TODO Convert to hash table (A)
        foreach ($prop in $object.psobject.Properties)
        {
            if ($prop.Value -is [array]) # TODO Check for `-is [psobject]` as well
            {
                $counter = 0
                foreach ($value in $prop.Value)
                {
                    if ($value -is [array]) { New-FlatObject -object $value }
                    $returnObject | Add-Member -MemberType NoteProperty -Name "$($prop.Name)$counter" -Value $value # TODO (A)
                    $counter++
                }
            }
            else
            {
                $returnObject | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value # TODO (A)
            }
        }
        return $returnObject # TODO (A)
    }
}

# TODO (A) $returnHT["$($prop.Name)$counter"] = $value
# TODO (A) return [PSCustomObject]$returnHT
