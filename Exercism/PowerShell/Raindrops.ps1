Function Get-Raindrops() {
    <#
    .SYNOPSIS
    Given a number convert it to Pling, Plang, Plong if it has factors of 3, 5 or 7.
    
    .DESCRIPTION
    Convert a number to a string, the contents of which depend on the number's factors.

    - If the number has 3 as a factor, output 'Pling'.
    - If the number has 5 as a factor, output 'Plang'.
    - If the number has 7 as a factor, output 'Plong'.
    - If the number does not have 3, 5, or 7 as a factor, just pass the number's digits straight through.
    
    .PARAMETER Rain
    The number to evaluate
    
    .EXAMPLE
    Get-Raindrops -Rain 35

    This will return PlangPlong as it has factors of 5 and 7

    .EXAMPLE
    Get-Raindrops -Rain 12121

    This will return 12121 as it does not contain factors of 3, 5 or 7 so the value is passed through.

Introduction
Raindrops is a slightly more complex version of the FizzBuzz challenge, a classic interview question.

Instructions
Your task is to convert a number into its corresponding raindrop sounds.

If a given number:

is divisible by 3, add "Pling" to the result.
is divisible by 5, add "Plang" to the result.
is divisible by 7, add "Plong" to the result.
is not divisible by 3, 5, or 7, the result should be the number as a string.
Examples
28 is divisible by 7, but not 3 or 5, so the result would be "Plong".
30 is divisible by 3 and 5, but not 7, so the result would be "PlingPlang".
34 is not divisible by 3, 5, or 7, so the result would be "34".

    #>
    [CmdletBinding()]
    Param(
        [int]$Rain
    )

    Throw "Please implement this function"
}