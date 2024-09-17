$colorHash = [ordered]@{
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

Function Get-ColorCode() {
    <#
    .SYNOPSIS
    Translate a color to its corresponding color code.

    .DESCRIPTION
    Given a color, return its corresponding color code.

    .PARAMETER Color
    The color to translate to its corresponding color code.

    .EXAMPLE
    Get-ColorCode -Color "black"
    #>
    [CmdletBinding()]
    Param(
        [string]$Color
    )

    return $colorHash.$Color
}

Function Get-Colors() {
    <#
    .SYNOPSIS
    Return the list of all colors.

    .DESCRIPTION
    Return the list of all colors.

    .EXAMPLE
    Get-Colors
    #>
    
    return $colorHash.Keys
}