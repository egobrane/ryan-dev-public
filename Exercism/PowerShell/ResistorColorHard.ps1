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

Function Get-ResistorLabel() {
    <#
    .SYNOPSIS
    Implement a function to get the label of a resistor with three color-coded bands.

    .DESCRIPTION
    Given an array of colors from a resistor, decode their resistance values and return a string represent the resistor's label.

    .PARAMETER Colors
    The array repesent the 3 colors from left to right.

    .EXAMPLE
    Get-ResistorLabel -Colors @("red", "white", "blue")
    Return: "29 megaohms"
    #>
    [CmdletBinding()]
    Param(
        [string[]]$Colors
    )
    for ($i = 0; $i -lt 3; $i ++)
    {
        $colorCheck = $Colors[$i]
        switch ($i)
        {
            {$i -eq 0}
            {
                $transistorCount += $colorHash.$colorcheck
                $transistorCount *= 10
                continue
            }
            {$i -eq 1}
            {
                $transistorCount += $colorHash.$colorcheck
                continue
            }
            {$i -eq 2}
            {
                $finalColor = $colorHash.$colorCheck
                if ($finalColor -ne 0)
                {
                    $zeroes = "{0:D$finalColor}" -f 0
                    $hundreds = "1" + "$zeroes"
                    $exponent = [int]$hundreds
                    $transistorCount *= $exponent
                }
            }
        }
    }
    $metricCount = ($transistorCount.ToString().ToCharArray() | Where-Object { $_ -eq '0' }).Count
    switch ($metricCount)
    {
        {$metricCount -ge 9}
        {
            $metricPrefix = "gigaohms"
            $transistorCount /= 1000000000
            break
        }
        {$metricCount -ge 6}
        {
            $metricPrefix = "megaohms"
            $transistorCount /= 1000000
            break
        }
        {$metricCount -ge 3}
        {
            $metricPrefix = "kiloohms"
            $transistorCount /= 1000
            break
        }
        Default
        {
            $metricPrefix = "ohms"
        }
    }
    
    return "$transistorCount $metricPrefix"
}

Get-ResistorLabel -Colors @("blue", "green", "yellow", "orange")