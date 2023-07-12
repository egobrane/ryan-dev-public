#This is a function to format XML files in a structure that can be used by the DSC file resource to manually place the contents of a policy. 
#It is no longer needed because the new applocker DSC implementation does not manually place contents of a file. 

function Format-XML ([xml]$xml, $indent=2)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = "indented"
    $xmlWriter.Indentation = $indent
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    Write-Output $StringWriter.ToString()
}
Format-XML ([xml](Get-AppLockerPolicy -Effective -Xml)) -indent 2 |
Out-File -FilePath "C:\Temp\Applocker-pol.xml" -Encoding ascii