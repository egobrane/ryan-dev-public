Function Invoke-Panagram() {
    <#
    .SYNOPSIS
    Determine if a sentence is a pangram.
    
    .DESCRIPTION
    A pangram is a sentence using every letter of the alphabet at least once.
    
    .PARAMETER Sentence
    The sentence to check
    
    .EXAMPLE
    Invoke-Panagram -Sentence "The quick brown fox jumps over the lazy dog"
    
    Returns: $true
    #>
    [CmdletBinding()]
    Param(
        [string]$Sentence
    )

    $lowerSentence = $Sentence.ToLower()
    $pangramCheck = $lowerSentence.ToCharArray()
	$trimmedArray = $pangramCheck | ForEach-Object { $_.Trim() }
	$count = $trimmedArray | Get-Unique

	if ($count.Length -eq 26)
	{
		$true
	}
	else
	{
		$false
	}
}

Invoke-Panagram "the quick brown fox jumped over the lazy dog"