# Get a list of servers in the domain
$Allservers = Get-ADComputer -Filter {OperatingSystem -Like "*server*"} -Property Name | Select-Object -ExpandProperty Name

$ErrorPath = $PSScriptRoot

$failedDNSServers = @()
$servers = @()

foreach ($server in $Allservers) {
    if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet)) {
        $failedDNSServers += $server
    }
    else {
    $servers += $server
    }
    }

$creds = get-credential

$failedM1Servers = @()
$failedM2Servers = @()

# Iterate through each server
foreach ($server in $servers) {
    # Create a script block for each server
    $scriptBlock = {

        # Get the computer name
        $computerName = $env:COMPUTERNAME

        # Get the IP address
        $ipAddress = ((Test-Connection -ComputerName $computerName -Count 1).IPv4Address.IPAddressToString)

        # Get the DNS server addresses
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses

        # Specify the centralized network share path
        $centralizedPath = "*Insert Network Share Here*"
        

        # Get the operating system version
        $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version

        # Get the list of installed software
        $installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version

        # Create a custom object with computer name, OS version, and installed software
        $result = foreach ($software in $installedSoftware) {
            [PSCustomObject]@{
                "SoftwareName" = $software.Name
                "SoftwareVersion" = $software.Version
            }
        }

        # Get CPU usage percentage
        $cpuUsage = Get-WmiObject -Class Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average
        
        # Get CPU information including sockets and cores
        $cpus = Get-WmiObject -Class Win32_Processor
        $cpuSockets = $cpus | Select-Object -Property SocketDesignation -Unique
        $cpuCores = $cpus | Measure-Object -Property NumberOfCores -Sum | Select-Object -ExpandProperty Sum

        # Get memory information
        $memory = Get-WmiObject -Class Win32_OperatingSystem
        $memoryTotal = $memory.TotalVisibleMemorySize
        $memoryFree = $memory.FreePhysicalMemory
        
        # Get disk information
        $disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, Size, FreeSpace

        $diskUsage = foreach ($disk in $disks) {
        $diskID = $disk.DeviceID
        $diskSize = $disk.Size
        $diskFree = $disk.FreeSpace
        $diskFreePercentage = ($diskFree / $diskSize) * 100

        [PSCustomObject]@{
        DeviceID = $diskID
        FreePercentage = $diskFreePercentage
        }
        }

        $systemReport = [PSCustomObject]@{
        "CPUUsage" = $cpuUsage
        "CPUSockets" = $cpuSockets.Count
        "CPUCores" = $cpuCores
        "MemoryTotal" = $memoryTotal
        "MemoryFree" = $memoryFree
        "DiskUsage" = $diskUsage
        "ComputerName" = $computerName
        "IPAddress" = $ipAddress
        "DNSServers" = $dnsServers -join ","
        "OSVersion" = $osVersion
        }

        
        $firewallStatus = Get-NetFirewallProfile

        
        $sysevents = Get-WinEvent -LogName System -FilterXPath "*[System[(Level=2)]]" -MaxEvents 100
        $appevents = Get-WinEvent -LogName Application -FilterXPath "*[System[(Level=2)]]" -MaxEvents 100




        #Export
        New-Item -ItemType Directory -Path "$centralizedPath\$computerName"
        $systemReport | Export-Csv -Path "$centralizedPath\$computerName\System.csv" -NoTypeInformation
        $sysevents | Export-Csv -Path "$centralizedPath\$computerName\SystemEvents.csv" -NoTypeInformation
        $appevents | Export-Csv -Path "$centralizedPath\$computerName\ApplicationEvents.csv" -NoTypeInformation
        $firewallStatus | Out-File -FilePath "$centralizedPath\$computerName\firewall_status.txt"
        $result | Export-Csv -Path "$centralizedPath\$computerName\InstalledSoftware.csv" -NoTypeInformation

        # Output a success message
        Write-Host "Installed software list exported to $centralizedPath\$computerName\"
    }

    #Method 1
    try {
    Invoke-Command -ComputerName $server -ScriptBlock $scriptBlock -Credential $creds -ErrorAction Stop
    }
    Catch {
    Write-host "Error connecting to $server "
    $failedM1Servers += [PSCustomObject]@{
            Server = $server
            Error = $_.Exception.Message
            }
    }

    #Method2
    try {
    Invoke-CommandAs -ComputerName $server -ScriptBlock $scriptBlock -Credential $creds -AsUser $creds -ErrorAction Stop
    }
    Catch {
    Write-host "Error connecting to $server "
    $failedM2Servers += [PSCustomObject]@{
            Server = $server
            Error = $_.Exception.Message
            }
    }

}
# Specify the path and file name for the output file
$exportM1Path = "$ErrorPath\failed_M1_servers.txt"
$exportM2Path = "$ErrorPath\failed_M2_servers.txt"
$exportDNSPath = "$ErrorPath\failed_DNS_servers.txt"

# Write the failed servers and their error messages to the output file
$failedM1Servers | Export-Csv -Path $exportM1Path -NoTypeInformation
$failedM2Servers | Export-Csv -Path $exportM2Path -NoTypeInformation
$failedDNSServers | Export-Csv -Path $exportDNSPath -NoTypeInformation