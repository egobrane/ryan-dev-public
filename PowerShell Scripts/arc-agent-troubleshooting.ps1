#Requires -RunAsAdministrator
Enum ArcLoggerLevel {
    Debug = 1
    Info = 2
    Warn = 3
    Error = 4
    Fatal = 5
}



class ArcLogger {
    [string]$log_path


    ArcLogger([string]$path) {
        if (![System.IO.File]::Exists($path)) {
            try {
                new-item -Path $path -ItemType File
            }
            catch {
                throw "Failed to initialize logger: $($Error[0].InnerException)"
            }
        }

        $this.log_path = $path
    }

    

    hidden [string]getTime() { return (get-date).ToString('yyyy-MM-dd hh:mm:ss') }

    hidden [string]parseArcLoggerLevel([string]$ArcLoggerLevel) { if ($ArcLoggerLevel.length -eq 4) { return "$ArcLoggerLevel " } else { return $ArcLoggerLevel } }

    hidden [string]parseSource([string]$name) {
        [int]$threshold = 20

        if ($name.length -gt $threshold) {
            throw "Error formatting Logger source: name is greater than $threshold"
        }
        
        $delta = $threshold - $name.length

        foreach ($i in 1..$delta) {
            $name += " "
        }
        return $name
    }

    [void]write([ArcLoggerLevel]$ArcLoggerLevel, [string]$source,[string]$message) {
        try {
            $this.writeToLog($ArcLoggerLevel,$source,$message)
            $this.writeToConsole($ArcLoggerLevel,$message,$true)
        } catch {
            Write-Error $Error[0].Exception.InnerException
        }
    }


    [void]writeToLog([ArcLoggerLevel]$ArcLoggerLevel, [string]$source,[string]$message) {
        
        $timestamp = $this.getTime()
        $log_ArcLoggerLevel = $this.parseArcLoggerLevel($ArcLoggerLevel.tostring().ToLower())
        $source_name = $this.parseSource($source)

        try {
            Add-Content -Path $this.log_path -Value "$timestamp $log_ArcLoggerLevel $source_name $message"
        } catch {
            throw "Failed to write entry to log file: $_"
        }
    }

    [void]WriteTabletoLog([ArcLoggerLevel]$ArcLoggerLevel, [string]$source,[PSCustomObject]$table, [ScriptBlock] $expression) {
        $rows = New-Object System.Collections.ArrayList

        try {
            foreach ($row in $table) {
                $parsed_row = &$expression $row
                $this.writeToLog($ArcLoggerLevel,$source,$parsed_row)
            }
        } catch {
            throw "Failed to parse table and write to log: $_"
        }

    }

    [void]writeToConsole([ArcLoggerLevel]$ArcLoggerLevel,[string]$message,[bool]$UseNewLine) {
        $fg_color =  switch ($ArcLoggerLevel.value__) {
            1 { "DarkGray"}
            2 { "White" }
            3 { "Yellow"}
            4 { "Red"}
            5 { "DarkRed"}
            default {"White"}
        }

        if ($UseNewLine) {
            write-host "$message" -ForegroundColor $fg_color 
        } else {
            write-host -ForegroundColor $fg_color -NoNewline "$message"
        }

    }

} 








class ArcLogEntry {
    [ArcLoggerLevel]$level
    [System.DateTime]$time
    [string]$Message

    ArcLogEntry([string]$entry) {
        try {
            if ($entry -match 'time="(.+)" level=(\w+) msg="(.+)"') {
                $this.time = $Matches[1]
                $this.level = [ArcLoggerLevel]$Matches[2]
                $this.Message = $Matches[3]
            }
        }
        catch {
            throw "Failed to create a new Arc Log Entry: $_"
        }

    }

}

class ArcLogParser {
    [System.Collections.ArrayList] $Entries
    hidden [Hashtable] $ErrorsDictionary
    [System.Collections.ArrayList] $CaughtErrors

    ArcLogParser([string]$path) {
        $this.Entries = New-Object System.Collections.ArrayList

        if ($path -like "*azcmagent.log" -or $path -like "*himds.log") {
            $this.ParseAzCMAgentLog($path)
        }
        elseif ($path -like "*gc_ext.log") {
            $this.parseExtensionManagerLog($path)
        }
        else {
            throw "Unknown log type. Only familiar with azcmagent, himds & gc_ext"
        }

    }

    hidden [void]parseAzCMAgentLog([string]$path) {
        try {
            foreach ($row in (Get-Content -Path $path)) {
                $entry = [ArcLogEntry]::new($row)

                $this.Entries.Add($entry) | Out-Null

            }
        }
        catch {
            throw "Error parsing log '$path'. Error: $_"
        }
    }

    hidden [void]parseExtensionManagerLog([string]$path) {

    }
}

function filter-ArcLogParserEntries {
    [cmdletbinding()]
    Param (
        [ArcLoggerLevel]$LogLevel,
        [datetime]$Time,
        [string]$Range,

        [Parameter(Mandatory,ValueFromPipeline =$true)]
        [object]$InputObject

    )
    
    # Initialize function variables
    $entries = New-Object System.Collections.ArrayList
    $result = New-Object System.Collections.ArrayList

    # Perform validations on parameters
    if (([string]::IsNullOrEmpty($Range) -and ($null -ne $Time)) -or ($null -eq $Time -and ![string]::IsNullOrEmpty($Range))) {
        throw "Time or Range parameters are missing"
    }

    if ($null -ne $Time) {
            
        $old_time_limit = $new_time_limit = Get-Date

        if ($range -match '(\d+)h') {
            $old_time_limit = $time.AddHours(-1*([int]$Matches[1]))
            $new_time_limit = $time.AddHours([int]$Matches[1])
        }
        elseif ($range -match '(\d+)m') {
            $old_time_limit = $time.AddMinutes(-1*([int]$Matches[1]))
            $new_time_limit = $time.AddMinutes([int]$Matches[1])
        }
        elseif ($range -match '(\d+)s') {
            $old_time_limit = $time.AddSeconds(-1*([int]$Matches[1]))
            $new_time_limit = $time.AddSeconds([int]$Matches[1])
        }
        else{
            throw "Range variable not in the right format. Supported formats: ##h, ##m, ##s"
        }
    }

    if ($InputObject.GetType().Name -eq "ArcLogParser" -and !($InputObject.GetType().IsArray)) {
        $entries = $InputObject.Entries
    }
    elseif ($inputObject.GetType().Name -eq "ArcLogEntry") {
        $entries = $InputObject
    }
    else {
        throw "Unknown input object. Only accepting ArcLogParser or ArcLogEntry"
    }

    # Start filtering the results        
    if ($null -ne $Time) {
        $result = $entries | Where-Object {$_.time -ge $old_time_limit -and $_.time -le $new_time_limit}
    }

    if ($null -ne $LogLevel) {
        $result = $result | Where-Object {$_.level -eq $LogLevel}
    }


    return $result
}




function Get-TimestampForFolder {
    return (Get-Date).ToString("yyyy-MM-ddTHH-mm")
}

function Initialize-TemporaryDirectory {
    $dirname = "azcmagent-troubleshooter-"
    $dirName += Get-TimestampForFolder
    $dirName += "-"
    $dirName += $env:computername
    $path = ""

    try 
    {
        $path = [System.IO.Path]::GetTempPath() + $dirName 
        
        if ([System.IO.Directory]::Exists($path)) {
            Write-host "Temporary folder already exists, purging contents."
            Remove-Item -Path $path\* -Recurse | Out-Null        
        }
        else {
            New-Item -ItemType Directory -Path $path |Out-Null
        }   
    }
    catch 
    {
        Write-Error "Initialize-TemporaryDirectory error: $_"
    }

    return $path    
}

function Initialize-Script {
    $Global:WorkDir = Initialize-TemporaryDirectory
    $Global:EventLogsToCollect = [System.Collections.ArrayList]@("Application","System") 


    try {
        $Global:Logger = [ArcLogger]::new($Global:WorkDir + "\troubleshooter.log")
        
    }
    catch {
        Write-Error $_
        exit 1
    }
}

function Show-AgentDetails {
    try {
        $Global:AgentDetails = &"azcmagent" show -j | ConvertFrom-Json
    }
    catch {
        Write-Error $_
        exit 1
    }

    $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","Azure Connected Machine Agent Details")
    $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","$('-'*37)")
    $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","Machine Name:`t`t$($Global:AgentDetails.resourceName)")
    $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","Version:`t`t`t$($Global:AgentDetails.agentVersion)")
    $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","Region:`t`t`t`t$($Global:AgentDetails.location)")
    
    # Check if Proxy is enabled. If so - show proxy information
    if (![System.String]::IsNullOrEmpty($Global:AgentDetails.httpsProxy)) {
        $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","HTTP Proxy:`t`t`t`t$($Global:AgentDetails.httpsProxy)")

        # Check if Proxy Bass is enabled. If so - show bypass tags
        if (![System.String]::IsNullOrEmpty($Global:AgentDetails.proxyBypass)) {
        $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","Proxy Bypass:`t`t`t`t$($Global:AgentDetails.proxyBypass)")
        }
        else {
            $Global:Logger.writeToLog([ArcLoggerLevel]::Info,"Show-AgentDetails","Proxy Bypass:`t`t`t`tnot configured")
        }
    }
    else {
        $Global:Logger.writeToLog([ArcLoggerLevel]::Info,"Show-AgentDetails","HTTP Proxy:`t`t`t`tnot configured")
    }
    

    $Global:Logger.write([ArcLoggerLevel]::Info,"Show-AgentDetails","Status:`t`t`t`t$($Global:AgentDetails.status)")

    # Check there is any value for 'azcmagent show' errors . If so - show the concatenated error
    if (![System.String]::IsNullOrEmpty($Global:AgentDetails.agentErrorCode)) {
        $Global:Logger.write([ArcLoggerLevel]::Warn,"Show-AgentDetails","Agent Error Code:`t$($Global:AgentDetails.agentErrorCode): $($Global:AgentDetails.agentErrorDetails)")
    }

    # List services related to Arc Connected Machine Agent.
    # % There is some delay happining here on the select-object which I couldn't find its source.
    $Global:Logger.writeToConsole([ArcLoggerLevel]::Info,"Services:",$true)
    $Global:AgentDetails.services | Select-Object displayName,serviceName,status
    $Global:Logger.WriteTabletoLog([ArcLoggerLevel]::Info,"Show-AgentDetails",$Global:AgentDetails.services, {param($x) return "Service: $($x.displayName) ($($x.serviceName)): $($x.status)"})
}

function Verify-AzCMAgentInstalled  {
    $InstalledSoftware = (get-childitem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty).DisplayName
    if (!($InstalledSoftware -icontains "Azure Connected Machine Agent")) {
        Write-Error "Azure Connected Machine Agent is not installed on this machine."
        exit 1 
    }  
}

function Collect-WinEventLogs {
    Param
    (
        [Parameter(Mandatory=$True)]
        [String] $Source
    )

    $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-WinEventLogs","Collecting event log: `'$Source`'")


    try 
    {
        # Create Event Logs directory within work directory
        $event_logs_folder_path = $Global:WorkDir + "\Event Logs"
        if (!([System.IO.Directory]::Exists($event_logs_folder_path))) {
            New-Item -ItemType Directory -Path $event_logs_folder_path
        }

        # Fetch Event Log file from default event logs directory
        $windows_event_logs_folder_path ="$env:SystemRoot\System32\Winevt\Logs"
        $log_file = (get-childitem $windows_event_logs_folder_path | Where-Object {$_.Name -like "$Source.evtx"})[0].FullName

        if ([System.String]::IsNullOrEmpty($log_file)) {
            throw "Could not find Event Log `'$Source`' in `"$windows_event_logs_folder_path`""
        }

        # If the file was found - Copy it to the Event Logs directory within the work directory
        $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-WinEventLogs","Found event log: `'$log_file`'")

        $output_file = $event_logs_folder_path + "\$Source.evtx"
        Copy-Item -Path $log_file -Destination $output_file
        $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-WinEventLogs","$Source event log was saved to: `"$output_file`"")
    }
    catch
    {
        $Global:Logger.write([ArcLoggerLevel]::Error,"Collect-WinEventLogs","Failed to collect event log: $_")
    }
}

function collect-NetworkCheck {
    $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"collect-NetworkCheck","Performing network check")

    try {
        # Check if the host server is defined to use a private link by resolving the DNS address for his.
        # If the address resolves to 10.x.x.x or 172.x.x.x then we're running in a private link environment.
        $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"collect-NetworkCheck","Resolving DNS for `"gbl.his.arc.azure.com`" to determine if there's a use of Private Link")
        $his_ip = ([System.Net.Dns]::GetHostAddresses("gbl.his.arc.azure.com"))[0].IPAddressToString

        $check_result = ""

        # Check if IP starts with 10 or 172 and run 'azcmagent check' accordingly with or without '--use-private-link' flag
        if ($his_ip -match '(10|172).\d+.\d+.\d+') {
            $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"collect-NetworkCheck","Private Link Identified, will use --use-private-link flag")
            
            $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"collect-NetworkCheck","Running command: azcmagent check --location $($Global:AgentDetails.location) --use-private-link")
            $check_result = azcmagent check -j --location $Global:AgentDetails.location -p | convertfrom-json
        }
        else {
            $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"collect-NetworkCheck","Private Link not found.")
            $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"collect-NetworkCheck","Running command: azcmagent check --location $($Global:AgentDetails.location)")
            $check_result = azcmagent check -j --location $($Global:AgentDetails.location) | convertfrom-json
        }

        # Display results to console
        $Global:Logger.writeToConsole([ArcLoggerLevel]::Info,"Network Availability check",$true)
        $Global:Logger.writeToConsole([ArcLoggerLevel]::Info,"--------------------------",$false)
        $check_result | select endpoint,reachable,Required,Private,tls,'proxy status' | ft

        # Write table results to the log
        $Global:Logger.WriteTabletoLog([ArcLoggerLevel]::Info,"collect-NetworkCheck", $check_result.PSObject.Properties, {param($x) return "Endpoint: `"$($x.Name)`" | Reachable: `"$($x.value.reachable)`" | Private IP: `"$($x.value.private)`" | TLS: `"$($x.tls)`" | Proxy Status: `"$($x.value.proxyStatus)`""})
    }
    catch {
        $Global:Logger.write([ArcLoggerLevel]::Error,"Collect-NetworkCheck","Failed perform network check: $_")
    }
}

function Zip-Collection {
    $zip_name = "$Global:WorkDir.zip"
    $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Zip-Collection","Compressing all logs")
    
    try {
        # Compress work directory info a zip file with the same name
            
        Compress-Archive -Path "$Global:WorkDir" -DestinationPath "$zip_name" -CompressionLevel Optimal

        # Remove work directory to clear waste files
        Remove-Item -Recurse -Force -Path $Global:WorkDir
        $Global:Logger.writeToConsole([ArcLoggerLevel]::Info,"Logs saved into `"$zip_name`"",$true)

        # Open the directory where the zip file was saved.
        & "explorer" "/select,$zip_name"
    }
    catch {
        $Global:Logger.writeToConsole([ArcLoggerLevel]::Error,"Failed to zip work directory: $_",$true)
    }

}

function Collect-Logs {
    $zip_name = $Global:WorkDir + "\azcmagent-logs-$(Get-TimestampForFolder)-$env:COMPUTERNAME.zip"
    $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-Logs","Running: azcmagent logs -o `"$zip_name`"")
    
    
    try {
        azcmagent logs -o "$zip_name" | Out-Null
        
        $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-Logs","Logs were saved to: `"$zip_name`"")
    }
    catch {
        $Global:Logger.write([ArcLoggerLevel]::Error,"Collect-Logs","Failed to collect agent logs: $_")
    }
}

function Collect-OSInfo {
    $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-OSInfo","Collecting OS information")
    
    
    try {
        # Create report file within work directory named 'OSInfo.txt'
        $report_file = $Global:WorkDir + "\OSInfo.txt"
        New-Item -ItemType File -Path $report_file

        # Capture data using CIM or CLI commands.
        # Not using Get-ComputerInfo due to long execution duration.
        $OS_info = Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption,Version,LocalDateTime
        $timezone_info = Get-CimInstance -ClassName Win32_TimeZone -Property Caption
        
        # Add OS informations to report file
        Add-Content -Path $report_file -Value "OS Information`n=============="
        Add-Content -Path $report_file -Value "Operating System:`t$($OS_info.Caption)"
        Add-Content -Path $report_file -Value "Version:`t`t$($OS_info.Version)"

        # Add Time information to report file
        Add-Content -Path $report_file -Value "`n`Time Settings`n================"
        Add-Content -Path $report_file -Value "Time Zone:`t$($timezone_info.Caption)"
        Add-Content -Path $report_file -Value "Local Time:`t$($OS_info.LocalDateTime)"

        # Add network information to report file
        Add-Content -Path $report_file -Value "`n`nNetwork Settings`n================"
        Add-Content -Path $report_file -Value $(ipconfig)
        Add-Content -Path $report_file -Value  "`n*************************************************************"
        Add-Content -Path $report_file -Value $(route print)
        Add-Content -Path $report_file -Value  "`n*************************************************************"
        Add-Content -Path $report_file -Value  "Enabled SSL/TLS:`t$([Net.ServicePointManager]::SecurityProtocol)"

        $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-OSInfo","Saved OS information to file: `"$report_file`"")
    }
    catch {
        $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-OSInfo","Failed to collect OS info: $_")
    }
}

function Collect-Extesions {
    $extension_report_folder = "C:\ProgramData\GuestConfig\extension_reports\"
    $Global:Logger.writeToLog([ArcLoggerLevel]::Debug,"Collect-Extesions","Collecting Extensions reports from folder: `"$extension_report_folder`"")

    
    # Iterate extensions reports files under  GuestConfig folder
    # For each, create a custom PSObject and add it into an array to create a table-like object
    $Global:Extensions = New-Object System.Collections.ArrayList
    
    try {
        Get-ChildItem $extension_report_folder | ForEach-Object {
            $json = Get-Content -Path $_.FullName | ConvertFrom-Json
            $ext = New-Object psobject

            $ext | Add-Member -MemberType NoteProperty -Name "Name" -Value $json.name
            $ext | Add-Member -MemberType NoteProperty -Name "ProvisioningState" -Value $json.status.provisioningState
            $ext | Add-Member -MemberType NoteProperty -Name "StatusLevel" -Value $json.status.statusLevel
            $ext | Add-Member -MemberType NoteProperty -Name "StatusMessage" -Value $json.status.statusMessage

            $Global:Extensions.Add($ext) | Out-Null

            $Global:Logger.writeToLog([ArcLoggerLevel]::Info,"Collect-Extesions","Name: `"$($ext.Name)`"`t| Provisioning State: `"$($ext.ProvisioningState)`"`t| Status Level: `"$($ext.StatusLevel)`"`t| Status Message: `"$($ext.StatusMessage)`"")
        }
    } catch {
        $Global:Logger.write([ArcLoggerLevel]::Error,"Collect-Extesions","Failed to extensions reports: $_")
    }
}

Write-Output "####################################################"
Write-Output "Azure Connected Machine Agent Troubleshooter Script"
Write-Output "####################################################`n"

Verify-AzCMAgentInstalled

Initialize-Script

Show-AgentDetails

Collect-Logs

foreach ($log in $Global:EventLogsToCollect) {
    Collect-WinEventLogs -Source $log
} 

Collect-Extesions

Collect-OSInfo

collect-NetworkCheck

Zip-Collection
