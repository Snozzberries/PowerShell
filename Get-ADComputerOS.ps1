$s = @("forest.tld","child.forest.tld","child2.forest.tld")
$x = $null

$s | %{$x += Get-ADComputer -Filter 'ObjectClass -like "Computer"' -Properties operatingSystem -server $_}

$x | group operatingSystem | select name, count | sort name
$x | Export-Csv $env:USERPROFILE\Desktop\computers.csv
