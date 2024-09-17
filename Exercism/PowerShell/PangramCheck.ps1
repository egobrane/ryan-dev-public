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

    $sentenceArray = $Sentence.ToLower().ToCharArray()
	$count = $sentenceArray | Where-Object {$_ -match "[a-z]"} | Select-Object -Unique
    $clearCount = $count | Where-Object {$_ -ne $null}

	if ($clearCount.Length -ge 26)
	{
		$true
	}
	else
	{
		$false
	}
}