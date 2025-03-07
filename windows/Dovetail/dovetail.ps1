# Author: Altoid0 (https://twitter.com/Altoid0day)
# PowerShell script dispatcher tool
<# 
.SYNOPSIS
    Remote PowerShell script dispatcher 

.DESCRIPTION
    Remote management over WinRM to automate async script deployment and output collection. Initially developed for the Collegiate Cyber Defense Competition. So if you see some garbage that doesn't make sense it was probably a design choice made specifically for competition use.

.PARAMETER Host
    Path of file containing newline separated hosts to target

.PARAMETER Script
    Path of the script to dispatch

.PARAMETER FunctionCall
    Function name and accompanying arguments if a specific function from a script should be executed

.PARAMETER NonDomain
    Indicates that the script is being run on a system that is outside of the target hosts' domain

.PARAMETER Connect
    Switch that tells the script to initiate WinRM sessions to each of the target hosts
    
.PARAMETER Repair
    Repair existing WinRM sessions that may have been broken due to network hiccups

.PARAMETER Out
    Path of the output directory for script execution logs

.PARAMETER Include
    Of all the hosts provided with the file in the -Hosts parameter, pick select ones. Must follow the same convention used in Hosts.txt. If IP addresses were specified then -Include must be a list of Ips, if Domain mode is used or if hostnames were used then -Include must use hostnames

.PARAMETER Exclude
    Inverse of Include

.PARAMETER Timeout
    Timeout in milliseconds for testing network connectivity to the target computer's ports

#>

Param(
    [Parameter(Mandatory = $false)]
    [String]$Hosts,

    [Parameter(Mandatory = $false)]
    [String]$Script,

    [Parameter(Mandatory = $false)]
    [String]$FunctionCall,

    [Parameter(Mandatory = $false)]
    [switch]$NonDomain,

    [Parameter(Mandatory = $false)]
    [switch]$Connect,

    [Parameter(Mandatory = $false)]
    [switch]$Repair,

    [Parameter(Mandatory = $false)]
    [String]$Out = "$(Get-Location)\Logs",

    [Parameter(Mandatory = $false)]
    [String[]]$Include,

    [Parameter(Mandatory = $false)]
    [String[]]$Exclude,

    [Parameter(Mandatory = $false)]
    [Int]$Timeout = 3000,

    [Parameter(Mandatory=$false)]
    [switch]$Rotate,

    [Parameter(Mandatory=$false)]
    [switch]$Backup
)

# ErrorActionPreferenece's opinion doesn't matter here
$ErrorActionPreference = "Continue"

<#
.SYNOPSIS
    Establish sessions to targets

.DESCRIPTION
    Establish WinRM sessions over port 5985 or 5986 depending on what is open on each given host. Sessions are saved in a global variable for later access.

.PARAMETER Computer
    IP, hostname, or FQDN of the target computer

.PARAMETER NonDomain
    Indicate that the current client is not in the some domain or part of a trusted domain, relative to the target computers. When this parameter is specified the $global:Cred value is used. 

.PARAMETER Timeout
    Timeout in milliseconds for testing network connectivity to the target computer's ports

.EXAMPLE
    Connect-WinRMPSSession -Computer $Computer -NonDomain -Timeout $Timeout
#>
function Connect-WinRMPSSession {
    Param(
        [Parameter(Mandatory = $true)]
        [string[]]$Computers,
        [switch]$NonDomain,
        [Int]$Timeout = 3000
    )

    # Test ports for all computers in parallel
    $WinRMAbleHosts = Test-Port -Computers $Computers -Port 5985 -Timeout $Timeout
    # Output is an array of maps with Computer, IsOpen, and Port properties

    foreach($WinRMAble in $WinRMAbleHosts) {
        if ($WinRMAble.Port -eq 5985) {
            if ($NonDomain) {
                $session = New-PSSession -ComputerName $WinRMAble.Computer -Credential $global:Cred -ErrorAction SilentlyContinue
            } else {
                $session = New-PSSession -ComputerName $WinRMAble.Computer -ErrorAction SilentlyContinue
            }
        } elseif ($WinRMAble.Port -eq 5986) {
            if ($NonDomain) {
                $session = New-PSSession -ComputerName $WinRMAble.Computer -Credential $global:Cred -UseSSL -SessionOption @{SkipCACheck=$true;SkipCNCheck=$true;SkipRevocationCheck=$true} -ErrorAction SilentlyContinue
            } else {
                $session = New-PSSession -ComputerName $WinRMAble.Computer -UseSSL -SessionOption @{SkipCACheck=$true;SkipCNCheck=$true;SkipRevocationCheck=$true} -ErrorAction SilentlyContinue
            }
        }

        if ($null -ne $session) {
            $global:Sessions += $session
            Write-Host "[INFO] Connected: $($WinRMAble.Computer)" -ForegroundColor Green
            if ($Rotate) {
                Invoke-Command -Session $session -ScriptBlock {
                    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                    if (($domainRole -eq 4 -or $domainRole -eq 5)){
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                    }
                }
                $password_change = Read-Host "Do you want to change password? $($WinRMAble.Computer) (yes or no)"
                if ($password_change -eq "yes") {
                    $password = Read-Host "Enter password for $($WinRMAble.Computer)"
                    Invoke-Command -Session $session -ScriptBlock {
                        net user Administrator $using:password
                    }  
                }
            }

            if ($Backup) {
                Write-Host "Creating backup user for $($WinRMAble.Computer)"
                Invoke-Command -Session $session -ScriptBlock {
                    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                    if (!($domainRole -eq 4 -or $domainRole -eq 5)){
                        $Name = Read-Host "Enter username for backup user for $($WinRMAble.Computer)"
                        $params = @{
                            Name        = $Name
                            Password    =  Read-Host "Enter password for backup user for $($WinRMAble.Computer)" -AsSecureString
                        }
                        New-LocalUser @params

                        Add-LocalGroupMember -Group "Administrators" -Member $Name
                        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Name
                    } elseif (($domainRole -eq 4 -or $domainRole -eq 5)){
                        $Name = Read-Host "Enter username for backup user for $($WinRMAble.Computer)"
                        $params = @{
                            Name        = $Name
                            Password    =  Read-Host "Enter password for backup user for $($WinRMAble.Computer)" -AsSecureString
                        }
                        New-LocalUser @params

                        Add-ADGroupMember -Identity "Domain Admins" -Members $Name
                    }
                }
            }           
        } else {
            Write-Host "[ERROR] WinRM Connection Failed: $($WinRMAble.Computer)" -ForegroundColor Red
        }
    }
}

<#
.SYNOPSIS
    Port scanning with parallelization

.DESCRIPTION
    Tests if a specific port is open on multiple computers simultaneously using PowerShell jobs

.PARAMETER Computers
    Array of IP addresses, hostnames, or FQDNs to test

.PARAMETER Port
    Port

.PARAMETER Timeout
    Timeout in milliseconds for testing network connectivity

.PARAMETER Verbose
    Controls optional debug messages

.EXAMPLE
$OpenComputers = Test-Port -Computers $ComputerList -Port 5985 -Timeout $Timeout -Verbose

.NOTES
Returns an array of computers where the specified port is open
#>
function Test-Port {
    Param(
        [Parameter(Mandatory = $true)]
        [string[]]$Computers,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [int]$Timeout = 3000,
        [switch]$VerboseOutput
    )

    $ErrorActionPreference = "SilentlyContinue"
    $WinRMAbleHosts = @()
    $Jobs = @()

    # Create a scriptblock that will be used for each job
    $scriptBlock = {
        param($Computer, $Port, $Timeout, $VerboseFlag)
        $ErrorActionPreference = "SilentlyContinue"
        $tcpclient = New-Object System.Net.Sockets.TcpClient
        $iar = $tcpclient.BeginConnect($Computer, $Port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne($Timeout, $false)

        if (!$wait) {
            # Connection timeout
            $tcpclient.Close()
            if ($VerboseFlag) { Write-Host "[WARN] $($Computer):$Port Connection Timeout " -ForegroundColor Yellow}
            $ReturnMap = @{Computer = $Computer; IsOpen = $false; Port = $Port}
        } 
        else {
            # Check for connection errors
            $failed = $false
            $error.Clear()
            try {
                $tcpclient.EndConnect($iar) | Out-Null
                if (!$?) { $failed = $true }
            }
            catch {
                $failed = $true
            }
            finally {
                $tcpclient.Close()
            }

            $ReturnMap = @{Computer = $Computer; IsOpen = !$failed; Port = $Port}
        }

        # If the port is not open, check for WinRM over HTTPS
        if (!$ReturnMap.IsOpen) {
            # Recursive call
            # Yes I hardcoded the port number
            $ReturnMap = Test-Port -Computers @($Computer) -Port 5986 -Timeout $Timeout -VerboseOutput:$VerboseFlag
            if (!$ReturnMap.IsOpen) {
                Write-Host "[ERROR] $($Computer): No WinRM Ports Open" -ForegroundColor Red
            }
        }

        return $ReturnMap
    }

    # Create a job for each computer
    foreach ($Computer in $Computers) {
        $Jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $Computer, $Port, $Timeout, $VerboseOutput
    }

    # Wait for all jobs to complete
    $null = Wait-Job -Job $Jobs

    # Collect results
    foreach ($Job in $Jobs) {
        $result = Receive-Job -Job $Job
        if ($result.IsOpen) {
            $WinRMAbleHosts += $result
            if ($Verbose) { Write-Host "[INFO] $($result.Computer):$Port is open" -ForegroundColor Green }
        }
        Remove-Job -Job $Job -Force
    }

    return $WinRMAbleHosts
}

# Core script logic:

# Connection logic
if ($Connect) {

    # Clear all the global variables unless we're repairing sessions
    if (!$Repair) {
        Remove-Variable -Name Sessions -Scope Global -ErrorAction SilentlyContinue;
        Remove-Variable -Name Denied -Scope Global -ErrorAction SilentlyContinue;
        $global:Sessions = @()
        $global:Denied = @()
        # When there are a lot of sessions this can take a while, haven't been able to find an alternative way to run this in the background
        Get-PSSession | Remove-PSSession
    }
    else {
        if ($global:Sessions.Count -eq 0) {
            Write-Host "[ERROR] No sessions" -ForegroundColor Red
            exit
        }
    }

    # If the target is in a different domain follow this stream of logic
    if ($NonDomain) {
        if ($null -eq $global:Cred) {
            $global:Cred = Get-Credential
        }
        
        # In the event that the -Repair param was used, identify failed sessions and recreate them
        if ($Repair) {
            for ($i = 0; $i -lt $global:Sessions.count; $i++) {
                if ($Sessions[$i].State -in @("Broken", "Disconnected", "Closed")) {
                    Connect-WinRMPSSession -Computers @($global:Sessions[$i].ComputerName) -NonDomain -Timeout $Timeout
                }
            }
        }

        # Normal logic for creating sessions to each host specified in the input file
        else {
            try {
                $Computers = Get-Content $Hosts
            }
            catch {
                Write-Host "[ERROR] Failed to get computers from file" -ForegroundColor Red
                exit
            }
    
            Connect-WinRMPSSession -Computers $Computers -NonDomain -Timeout $Timeout
        }
    }

    # If we are in the same domain, utilize WinRM with current user's creds
    else {
        # In the event that the -Repair param was used, identify failed sessions and recreate them
        if ($Repair) {
            for ($i = 0; $i -lt $global:Sessions.count; $i++) {
                if ($Sessions[$i].State -in @("Broken", "Disconnected", "Closed")) {
                    Connect-WinRMPSSession -Computers @($global:Sessions[$i].ComputerName) -Timeout $Timeout
                }
            }
        } 
        else {
            # Normal connection logic where the target computers are dynamically retrieved from the domain
            try {
                # Alegedly faster query command - Claude 3.7
                $Computers = Get-ADComputer -filter "OperatingSystem -like '*Windows*'" -Properties OperatingSystem | Select-Object -ExpandProperty Name            }
            catch {
                Write-Host "[ERROR] Failed to get computers from AD" -ForegroundColor Red
                exit
            }
    
            Write-Host "[INFO] Found the following servers:" -ForegroundColor Green
            foreach ($Computer in $Computers) {
                Write-Host "$Computer"
            }
            Connect-WinRMPSSession -Computers $Computers -Timeout $Timeout
        }
    }
}

# Script execution logic

# Ensure a script was passed, sessions exist, and the output path is not null
if (($Script -ne "") -and ($global:Sessions.Count -gt 0)) {

    
    # Clean up old jobs
    Get-Job | Remove-Job -Force

    # Make the output path of it doesn't exist
    if (!(Test-Path $Out)) {
        mkdir $Out
    }

    # Declare the Jobs array
    $Jobs = @()

    # Create a new randomized file extension to store script output per-host. This is a CCDC artifact since we didn't want script output to be easily enumerable for red teams.
    do {
        $Extension = ""
        $Extension += [System.IO.Path]::GetFileNameWithoutExtension($Script).ToLower() # Who made this a built in function :skull: :pray:
        $Extension += ".$(Get-Random -Maximum 1000)";
    } while (Test-Path "$Out\*.$Extension")

    # If a specific function call was provided, create a copy of the script and append the function call to the end of the new script
    if ($FunctionCall -ne "") {
        $FunctionName = $FunctionCall -split ' ' | Select-Object -First 1
        Remove-Item "C:\Windows\Temp\$FunctionName.ps1" -ErrorAction SilentlyContinue
        Write-Output (Get-Content $Script) | Out-File -FilePath "C:\Windows\Temp\$FunctionName.ps1" -Encoding utf8
        Write-Output $FunctionCall | Out-File -FilePath "C:\Windows\Temp\$FunctionName.ps1" -Encoding utf8 -Append
        $Script = "C:\Windows\Temp\$FunctionName.ps1"
    }

    # Iterate over all sessions and determine which to execute scripts against.
    foreach ($Session in $global:Sessions) {
        if ($Exclude.Count -gt 0 -and $Exclude -contains $Session.ComputerName) {
            Write-Host "[INFO] Excluded: $($Session.ComputerName)" -ForegroundColor Yellow
            continue
        }
        elseif ($Include.Count -gt 0 -and $Include -notcontains $Session.ComputerName) {
            Write-Host "[INFO] Did not Include: $($Session.ComputerName)" -ForegroundColor Yellow
            continue
        }

        if ($null -eq $Session -or $Session.State -in @("Broken", "Disconnected", "Closed")) {
            Write-Host "[ERROR] Session is cooked, skipping..." -ForegroundColor Red
            continue
        }

        $ScriptJob = Invoke-Command -FilePath $Script -Session $Session -AsJob
        $Jobs += $ScriptJob
        Write-Host "[INFO: $Script] Script invoked on $($Session.ComputerName)" -ForegroundColor Green
    }
    
    # Declare array of complete jobs
    $Complete = @()
    # Count total jobs
    $TotalJobs = $Jobs.count
    # Count incomplete jobs
    $IncompleteJobs = @()

    # While there are still running jobs, check the status of all jobs and clean up any that are finished
    while ($Complete.Count -lt $TotalJobs) {
        for ($i = 0; $i -lt $Jobs.count; $i++) {
            # Job States: https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.jobstate?view=powershellsdk-7.4.0
            # If the job is marked as completed and we have not collected it yet, gets its output
            if ($Jobs[$i].State -eq "Completed" -and $Complete -notcontains $Jobs[$i].Location) {
                $Jobs[$i] | Receive-Job | Out-File "$Out\$($Jobs[$i].Location).$Extension" -Encoding utf8
                Write-Host "[INFO: $Script] Script completed on $($Jobs[$i].Location) logged to $Extension" -ForegroundColor Green
                $Complete += $($Jobs[$i].Location)
            }

            # Add newly running jobs to the incomplete list
            elseif ($Jobs[$i].State -eq "Running" -and $Complete -notcontains $Jobs[$i].Location) {
                $IncompleteJobs += $Jobs[$i]
            }

            # If the job blew and we haven't observed this yet, mark it as complete for the sake of exiting the loop and notify the user
            elseif (($Jobs[$i].State -in @("Failed", "Blocked", "Disconnected", "Stopped", "Suspended")) -and $Complete -notcontains $Jobs[$i].Location) {
                Write-Host "[ERROR: $Script] Script $($Jobs[$i].State) on $($Jobs[$i].Location)" -ForegroundColor Red
                $Complete += $($Jobs[$i].Location)
            }
        }
        # As long as there are still jobs to wait for, replace the $Jobs array to only have in-progress jobs and reset the incomplete jobs array
        if ($IncompleteJobs.Count -ge 1) {
            $Jobs = $IncompleteJobs
            $IncompleteJobs = @()
            # Wait 25 milliseconds otherwise CPU/Mem usage spikes to 90%
            Start-Sleep -Milliseconds 25
        }
    }

    # Once done, clean up all old job artifacts that may be left
    Get-Job | Remove-Job -Force
}

# Error messages related to messed up input parameters
if ($global:Sessions.Count -eq 0 -and !$Connect) {
    Write-Host "[ERROR] No sessions" -ForegroundColor Red
}
if ($Script -eq '' -and !$Connect) {
    Write-Host "[ERROR] No script" -ForegroundColor Red
}
if ($Out -eq '' -and !$Connect) {
    Write-Host "[ERROR] No output directory" -ForegroundColor Red
}
