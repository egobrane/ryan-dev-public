function Convert-AzureAdObjectIdToSid {
    <#
    .SYNOPSIS
    Convert an Azure AD Object ID to SID
     
    .DESCRIPTION
    Converts an Azure AD Object ID to a SID.
    Author: Oliver Kieselbach (oliverkieselbach.com)
    The script is provided "AS IS" with no warranties.
     
    .PARAMETER ObjectID
    The Object ID to convert
    #>
    
        param([String] $ObjectId)
    
        $bytes = [Guid]::Parse($ObjectId).ToByteArray()
        $array = New-Object 'UInt32[]' 4
    
        [Buffer]::BlockCopy($bytes, 0, $array, 0, 16)
        $sid = "S-1-12-1-$array".Replace(' ', '-')
    
        return $sid
    }
    
    $objectId = "ce761d1a-18ae-4b71-82ea-974818cc5750"
    $sid = Convert-AzureAdObjectIdToSid -ObjectId $objectId
    Write-Output $sid
    