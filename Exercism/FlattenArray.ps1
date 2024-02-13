Function Invoke-FlattenArray() {
    <#
    .SYNOPSIS
    Take a nested array and return a single flattened array with all values except null.

    .DESCRIPTION
    Given an array, flatten it and keep all values execept null.

    .PARAMETER Array
    The nested array to be flatten.

    .EXAMPLE
    Invoke-FlattenArray -Array @(1, @(2, 3, $null, 4), @($null), 5)
    Return: @(1, 2, 3, 4, 5)
    #>
    [CmdletBinding()]
    Param(
        [System.Object[]]$Array
    )

    foreach ($object in $Array)
    {
        if (![string]::IsNullOrEmpty($object))
        {
            $flatArray += @($object)
        }
        if ([string]::IsNullOrEmpty($object))
        {

        }
    }
    $returnArray = $flatArray | Where-Object {$_ -ne $null} | Out-String -Stream
    return $returnArray
}

Invoke-FlattenArray -Array @($null, @(@(@($null))), $null, $null, @(@($null, $null), $null), $null)
