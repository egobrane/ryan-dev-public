Function Get-ColorCodeValue() {
    <#
    .SYNOPSIS
    Translate a list of colors to their corresponding color code values.

    .DESCRIPTION
    Given 2 colors, take the first one and times it by 10 and add the second color to it.

    .PARAMETER Colors
    The colors to translate to their corresponding color codes.

    .EXAMPLE
    Get-ColorCodeValue -Colors @("black", "brown")
    #>
    [CmdletBinding()]
    Param(
        [System.Object[]]$Colors
    )
    $colorHash = @{
        "black" = 0
        "brown" = 1
        "red" = 2
        "orange" = 3
        "yellow" = 4
        "green" = 5
        "blue" = 6
        "violet" = 7
        "grey" = 8
        "white" = 9
    }

    for ($i = 0; $i -lt 2; $i++)
    {
        $colorCheck = $Colors[$i]
        $transistorCount += $colorHash.$colorCheck
        if ($i -eq 0)
		{
			$transistorCount *= 10
		}
    }
    return $transistorCount
}

Get-ColorCodeValue -Colors @("green", "brown", "orange")
