function Test-LeapYear {
    <#
    .SYNOPSIS
    Given a year, report if it is a leap year.
    
    .DESCRIPTION
    Calculate whether the supplied year is a leap year. A leap year is determined from the following
    calculation:

    on every year that is evenly divisible by 4
    except every year that is evenly divisible by 100
    unless the year is also evenly divisible by 400
    
    .PARAMETER year
    The year to test
    
    .EXAMPLE
    Test-LeapYear -year 2018

    Returns false

    .EXAMPLE
    Test-LeapYear -year 2020

    Returns True

    Introduction
    A leap year (in the Gregorian calendar) occurs:

    In every year that is evenly divisible by 4.
    Unless the year is evenly divisible by 100, in which case it's only a leap year if the year is also evenly divisible by 400.
    Some examples:

    1997 was not a leap year as it's not divisible by 4.
    1900 was not a leap year as it's not divisible by 400.
    2000 was a leap year!
    #>
    param( [int]$year )

    return ($year % 4 -eq 0 -and (($year % 100 -ne 0) -or ($year % 400 -eq 0)))
    
}