Function Get-ResistorLabel() {
    <#
    .SYNOPSIS
    Implement a function to get the label of a resistor from its color-coded bands.

    .DESCRIPTION
    Given an array of 1, 4 or 5 colors from a resistor, decode their resistance values and return a string represent the resistor's label.

    .PARAMETER Colors
    The array represent the colors from left to right.

    .EXAMPLE
    Get-ResistorLabel -Colors @("red", "black", "green", "red")
    Return: "2 megaohms ±2%"

    Get-ResistorLabel -Colors @("blue", "blue", "blue", "blue", "blue")
    Return: "666 megaohms ±0.25%"

    Instructions
If you want to build something using a Raspberry Pi, you'll probably use resistors. Like the previous Resistor Color Duo and Resistor Color Trio exercises, you will be translating resistor color bands to human-readable labels.

Each resistor has a resistance value.
Resistors are small - so small in fact that if you printed the resistance value on them, it would be hard to read. To get around this problem, manufacturers print color-coded bands onto the resistors to denote their resistance values.
Each band acts as a digit of a number. For example, if they printed a brown band (value 1) followed by a green band (value 5), it would translate to the number 15.
Instructions
In this exercise, you are going to create a helpful program so that you don't have to remember the values of the bands. The program will take 1, 4, or 5 colors as input, and outputs the correct value, in ohms. The color bands are encoded as follows:

Black: 0
Brown: 1
Red: 2
Orange: 3
Yellow: 4
Green: 5
Blue: 6
Violet: 7
Grey: 8
White: 9
In resistor-color trio you decoded the first three colors. For instance: orange-orange-brown translated to the main value 330. In this exercise you will need to add tolerance to the mix. Tolerance is the maximum amount that a value can be above or below the main value. For example, if the last band is green, the maximum tolerance will be ±0.5%.

The tolerance band will have one of these values:

Grey - 0.05%
Violet - 0.1%
Blue - 0.25%
Green - 0.5%
Brown - 1%
Red - 2%
Gold - 5%
Silver - 10%
The four-band resistor is built up like this:

Band_1	Band_2	Band_3	band_4
Value_1	Value_2	Multiplier	Tolerance
Meaning

orange-orange-brown-green would be 330 ohms with a ±0.5% tolerance.
orange-orange-red-grey would be 3300 ohms with ±0.05% tolerance.
The difference between a four and five-band resistor is that the five-band resistor has an extra band to indicate a more precise value.

Band_1	Band_2	Band_3	Band_4	band_5
Value_1	Value_2	Value_3	Multiplier	Tolerance
Meaning

orange-orange-orange-black-green would be 333 ohms with a ±0.5% tolerance.
orange-red-orange-blue-violet would be 323M ohms with a ±0.10 tolerance.
There are also one band resistors. One band resistors only have the color black with a value of 0.

This exercise is about translating the resistor band colors into a label:

"... ohms ...%"

So an input of "orange", "orange", "black", "green" should return:

"33 ohms ±0.5%"

When there are more than a thousand ohms, we say "kiloohms". That's similar to saying "kilometer" for 1000 meters, and "kilograms" for 1000 grams.

So an input of "orange", "orange", "orange", "grey" should return:

"33 kiloohms ±0.05%"

When there are more than a million ohms, we say "megaohms".

So an input of "orange", "orange", "blue", "red" should return:

"33 megaohms ±2%"

        It "test orange orange black and red" {
            $got  = Get-ResistorLabel -Colors @("orange", "orange", "black", "red")
            $want = "33 ohms ±2%"
            $got | Should -BeExactly $want
        }
    
        It "test blue grey brown and violet" {
            $got  = Get-ResistorLabel -Colors @("blue", "grey", "brown", "violet")
            $want = "680 ohms ±0.1%"
            $got | Should -BeExactly $want
        }
    
        It "test red black red and green" {
            $got  = Get-ResistorLabel -Colors @("red", "black", "red", "green")
            $want = "2 kiloohms ±0.5%"
            $got | Should -BeExactly $want
        }
    
        It "test green brown orange and grey" {
            $got  = Get-ResistorLabel -Colors @("green", "brown", "orange", "grey")
            $want = "51 kiloohms ±0.05%"
            $got | Should -BeExactly $want
        }
    
        It "test one black band" {
            $got  = Get-ResistorLabel -Colors @("black")
            $want = "0 ohms"
            $got | Should -BeExactly $want
        }
    
        It "test orange orange yellow black and brown" {
            $got  = Get-ResistorLabel -Colors @("orange", "orange", "yellow", "black", "brown")
            $want = "334 ohms ±1%"
            $got | Should -BeExactly $want
        }
    
        It "test red green yellow yellow and brown" {
            $got  = Get-ResistorLabel -Colors @("red", "green", "yellow", "yellow", "brown")
            $want = "2.54 megaohms ±1%"
            $got | Should -BeExactly $want
        }
    
        It "test blue grey white red and brown" {
            $got  = Get-ResistorLabel -Colors @("blue", "grey", "white", "brown", "brown")
            $want = "6.89 kiloohms ±1%"
            $got | Should -BeExactly $want
        }
    
        It "test violet orange red and grey" {
            $got  = Get-ResistorLabel -Colors @("violet", "orange", "red", "grey")
            $want = "7.3 kiloohms ±0.05%"
            $got | Should -BeExactly $want
        }
    
        It "test brown red orange green and blue" {
            $got  = Get-ResistorLabel -Colors @("brown", "red", "orange", "green", "blue")
            $want = "12.3 megaohms ±0.25%"
            $got | Should -BeExactly $want
        }
     #>
    [CmdletBinding()]
    Param(
        [string[]]$Colors
    )
    Throw "Please implement this function"
}