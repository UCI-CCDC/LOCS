# PowerShell script dispatcher tool written initially for automating child script deployment at the Collegiate Cyber Defense Competition.
# Author: Altoid0 (https://twitter.com/Altoid0day)


param(
    [Parameter(Mandatory=$false)]
    [String]$Script = '',

    [Parameter(Mandatory=$false)]
    [switch]$Function,

    [Parameter(Mandatory=$false)]
    [String]$FunctionArgs = '',

    [Parameter(Mandatory=$false)]
    [String]$Out = "$(Get-Location)\Logs",

    [Parameter(Mandatory=$false)]
    [switch]$Connect,

    [Parameter(Mandatory=$false)]
    [switch]$Repair,

    [Parameter(Mandatory=$false)]
    [string[]]$Include,

    [Parameter(Mandatory=$false)]
    [string[]]$Exclude,

    [Parameter(Mandatory=$false)]
    [switch]$NonDomain,

    [Parameter(Mandatory=$false)]
    [String]$Hosts = '',

    [Parameter(Mandatory=$false)]
    [Int]$Timeout = 3000,

    [Parameter(Mandatory=$false)]
    [switch]$Rotate,

    [Parameter(Mandatory=$false)]
    [switch]$Machine,
    
    [Parameter(Mandatory=$false)]
    [switch]$Backup



)

$ErrorActionPreference = "Continue"

function Connect-WinRMSession {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Computer,
        [Parameter(Mandatory=$false)]
        [switch]$NonDomain,
        [Parameter(Mandatory=$false)]
        [Int]$Timeout = 3000
    )
    Write-Host "Trying to connect to $Computer" -ForegroundColor Magenta
    if (Test-Port -Ip $Computer -Port 5985 -Timeout $Timeout -Verbose) {
        if ($NonDomain) {
            $TestSession = New-PSSession -ComputerName $Computer -Credential $global:Cred -ErrorAction SilentlyContinue
        }
        else {
            $TestSession = New-PSSession -ComputerName $Computer -ErrorAction SilentlyContinue
        }
        if ($TestSession.State -eq "Opened") {
            $global:Sessions += $TestSession
            Write-Host "[INFO] Connected: $Computer" -ForegroundColor Green
            if ($Rotate) {
                Invoke-Command -Session $TestSession -ScriptBlock {
                    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                    if (($domainRole -eq 4 -or $domainRole -eq 5)){
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                    }
                }
                $password_change = Read-Host "Do you want to change password? $Computer (yes or no)"
                if ($password_change -eq "yes") {
                    $password = Read-Host "Enter password for $Computer"
                    Invoke-Command -Session $TestSession -ScriptBlock {
                        net user Administrator $using:password
                    }  
                }
            }
            if ($Machine) {
                $change_machine = Read-Host "Do you want to change the machine password for $Computer? (yes or no)"
                if ($change_machine -eq "yes") {
                    $cred = Get-Credential
                    Invoke-Command -ComputerName $Computer -ScriptBlock {Reset-ComputerMachinePassword -Credential $using:cred}
                    Invoke-Command -ComputerName $Computer -ScriptBlock {Reset-ComputerMachinePassword -Credential $using:cred}
                }
 
            }

            if ($Backup) {
                Write-Host "Creating backup user for $Computer"
                Invoke-Command -Session $TestSession -ScriptBlock {
                    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                    if (!($domainRole -eq 4 -or $domainRole -eq 5)){
                        $Name = Read-Host "Enter username for backup user for $Computer"
                        $params = @{
                            Name        = $Name
                            Password    =  Read-Host "Enter password for backup user for $Computer" -AsSecureString
                        }
                        New-LocalUser @params

                        Add-LocalGroupMember -Group "Administrators" -Member $Name
                        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Name
                    } elseif (($domainRole -eq 4 -or $domainRole -eq 5)){
                        $Name = Read-Host "Enter username for backup user for $Computer"
                        $params = @{
                            Name        = $Name
                            Password    =  Read-Host "Enter password for backup user for $Computer" -AsSecureString
                        }
                        New-LocalUser @params

                        Add-ADGroupMember -Identity "Domain Admins" -Members $Name
                    }
                }
            }           
        }
        else {
            $global:Denied += $Computer
            Write-Host "[ERROR] WinRM 5985 Failed: $Computer" -ForegroundColor Red
        }
    }
    elseif (Test-Port -Ip $Computer -Port 5986 -Timeout $Timeout -Verbose) {
        if ($NonDomain) {
            $TestSession = New-PSSession -ComputerName $Computer -Credential $global:Cred -UseSSL -SessionOption @{SkipCACheck=$true;SkipCNCheck=$true;SkipRevocationCheck=$true} -ErrorAction SilentlyContinue
        }
        else {
            $TestSession = New-PSSession -ComputerName $Computer -UseSSL -SessionOption @{SkipCACheck=$true;SkipCNCheck=$true;SkipRevocationCheck=$true} -ErrorAction SilentlyContinue
        }
        if ($TestSession.State -eq "Opened") {
            $global:Sessions += $TestSession
            Write-Host "[INFO] Connected SSL: $Computer" -ForegroundColor Green
            if ($Rotate) {
                Invoke-Command -Session $TestSession -ScriptBlock {
                    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                    if (($domainRole -eq 4 -or $domainRole -eq 5)){
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                        Write-Host "THIS IS DC!!!!!" -ForegroundColor Red -BackgroundColor Yellow
                    }
                }
                $password_change = Read-Host "Do you want to change password? $Computer (yes or no)"
                if ($password_change -eq "yes") {
                    $password = Read-Host "Enter password for $Computer"
                    Invoke-Command -Session $TestSession -ScriptBlock {
                        net user Administrator $using:password
                    }  
                }
            }

            if ($Machine) {
                $change_machine = Read-Host "Do you want to change the machine password for $Computer? (yes or no)"
                if ($change_machine -eq "yes") {
                    $cred = Get-Credential
                    Invoke-Command -ComputerName $Computer -ScriptBlock {Reset-ComputerMachinePassword -Credential $using:cred}
                    Invoke-Command -ComputerName $Computer -ScriptBlock {Reset-ComputerMachinePassword -Credential $using:cred}
                }
                
                
            }

            if ($Backup) {
                Write-Host "Creating backup user for $Computer"
                Invoke-Command -Session $TestSession -ScriptBlock {
                    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
                    if (!($domainRole -eq 4 -or $domainRole -eq 5)){
                        $Name = Read-Host "Enter username for backup user for $Computer"
                        $params = @{
                            Name        = $Name
                            Password    =  Read-Host "Enter password for backup user for $Computer" -AsSecureString
                        }
                        New-LocalUser @params

                        Add-LocalGroupMember -Group "Administrators" -Member $Name
                        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $Name
                    } elseif (($domainRole -eq 4 -or $domainRole -eq 5)){
                        $Name = Read-Host "Enter username for backup user for $Computer"
                        $params = @{
                            Name        = $Name
                            Password    =  Read-Host "Enter password for backup user for $Computer" -AsSecureString
                        }
                        New-LocalUser @params

                        Add-ADGroupMember -Identity "Domain Admins" -Members $Name
                        Add-ADGroupMember -Identity "Remote Desktop Users" -Members $Name
                    }
                }
            }           
            
        }
        else {
            $global:Denied += $Computer
            Write-Host "[ERROR] WinRM 5986 Failed: $Computer" -ForegroundColor Red
        }
    }
    else {
        $global:Denied += $Computer
        Write-Host "[ERROR] WinRM Ports Closed: $Computer" -ForegroundColor Red
    }

}

function Test-Port {
    Param(
        [string]$Ip,
        [int]$Port,
        [int]$Timeout = 3000,
        [switch]$Verbose
    )

    $ErrorActionPreference = "SilentlyContinue"

    $tcpclient = New-Object System.Net.Sockets.TcpClient
    $iar = $tcpclient.BeginConnect($ip,$port,$null,$null)
    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
    if (!$wait)
    {
        # Close the connection and report timeout
        $tcpclient.Close()
        if($verbose){Write-Host "[WARN] $($IP):$Port Connection Timeout " -ForegroundColor Yellow}
        return $false
    } 
    else {
        # Close the connection and report the error if there is one
        $error.Clear()
        $tcpclient.EndConnect($iar) | out-Null
        if(!$?){if($verbose){Write-Host $error[0] -ForegroundColor Red};$failed = $true}
        $tcpclient.Close()
    }

    if ($failed) {
        return $false
    }
    else {
        return $true
    }
}

if ($Connect) {

    if (!$Repair) {
        Remove-Variable -Name Sessions -Scope Global -ErrorAction SilentlyContinue;
        Remove-Variable -Name Denied -Scope Global -ErrorAction SilentlyContinue;
        $global:Sessions = @()
        $global:Denied = @()
        Get-PSSession | Remove-PSSession
    }

    if ($NonDomain) {
        if ($null -eq $global:Cred) {
            $global:Cred = Get-Credential
        }
        
        if ($Repair) {
            if ($global:Sessions.Count -eq 0) {
                Write-Host "[ERROR] No sessions" -ForegroundColor Red
                exit
            }
            else {
                for ($i = 0; $i -lt $global:Sessions.count; $i++) {
                    if ($Sessions[$i].State -eq "Broken" -or $Sessions[$i].State -eq "Disconnected" -or $Session.State -eq "Closed") {
                        Connect-WinRMSession -Computer $global:Sessions[$i].ComputerName -NonDomain -Timeout $Timeout
                    }
                }
            }
        } 
        else {
            try {
                $Computers = Get-Content $Hosts
            }
            catch {
                Write-Host "[ERROR] Failed to get computers from file" -ForegroundColor Red
                exit
            }
    
            foreach ($Computer in $Computers) {
                Connect-WinRMSession -Computer $Computer -NonDomain -Timeout $Timeout
            }
        }
    }
    else { # Domain WinRM with current user creds
        if ($Repair) {
            if ($global:Sessions.Count -eq 0) {
                Write-Host "[ERROR] No sessions" -ForegroundColor Red
                exit
            }
            else {
                for ($i = 0; $i -lt $global:Sessions.count; $i++) {
                    if ($Session.State -eq "Broken" -or $Session.State -eq "Disconnected" -or $Session.State -eq "Closed") {
                        Connect-WinRMSession -Computer $global:Sessions[$i].ComputerName -Timeout $Timeout
                    }
                }
            }
        } 
        else {
            try {
                $Computers = Get-ADComputer -filter * -Properties * | Where-Object OperatingSystem -Like "*Windows*" | Sort-Object | Select-Object -ExpandProperty Name
            }
            catch {
                Write-Host "[ERROR] Failed to get computers from AD" -ForegroundColor Red
                exit
            }
    
            Write-Host "[INFO] Found the following servers:" -ForegroundColor Green
            foreach ($Computer in $Computers) {
                Write-Host "$Computer"
            }
            foreach ($Computer in $Computers) {
                Connect-WinRMSession -Computer $Computer -Timeout $Timeout
            }
        }
    }
}

if (($Script -ne '') -and ($global:Sessions.Count -gt 0) -and ($Out -ne '')) {

    # Clean up old jobs
    Get-Job | Remove-Job -Force

    if (!(Test-Path $Out)) {
        mkdir $Out
    }
    $Jobs = @()
    do {
        $Extension = ""
        $Script = $Script.ToLower()
        $ScriptName = $Script.Split(".")[-2]
        $Extension += $ScriptName.Substring(1)
        $Extension += ".$(Get-Random -Maximum 1000)";
    } while (Test-Path "$Out\*.$Extension")

    if ($Function) {
        foreach ($line in (Get-Content $Script)) {
            if ($line -match "function") {
                $FunctionName = $line -replace "function ", ""
                $FunctionName = $FunctionName -replace "{", ""
                $FunctionName = $FunctionName.Trim()
                break
            }
        }
        Remove-Item "C:\Windows\Temp\$FunctionName.ps1" -ErrorAction SilentlyContinue
        Write-Output (Get-Content $Script) | Out-File -FilePath "C:\Windows\Temp\$FunctionName.ps1" -Encoding utf8
        Write-Output $FunctionName | Out-File -FilePath "C:\Windows\Temp\$FunctionName.ps1" -Encoding utf8 -Append -NoNewline

        if ($FunctionArgs -ne $null) {
            Write-Output $(" " + $FunctionArgs) | Out-File -FilePath "C:\Windows\Temp\$FunctionName.ps1" -Encoding utf8 -Append
        }
        $Script = "C:\Windows\Temp\$FunctionName.ps1"
    }

    foreach ($Session in $global:Sessions) {
        if ($Exclude.Count -gt 0 -and $Exclude -contains $Session.ComputerName) {
            Write-Host "[INFO] Excluded: $($Session.ComputerName)" -ForegroundColor Yellow
            continue
        }
        elseif ($Include.Count -gt 0 -and $Include -notcontains $Session.ComputerName) {
            Write-Host "[INFO] Did not Include: $($Session.ComputerName)" -ForegroundColor Yellow
            continue
        }

        if ($null -eq $Session -or $Session.State -eq "Broken" -or $Session.State -eq "Disconnected" -or $Session.State -eq "Closed") {
            Write-Host "[ERROR] Session is cooked, skipping..." -ForegroundColor Red
            continue
        }

        $ScriptJob = Invoke-Command -FilePath $Script -Session $Session -AsJob
        $Jobs += $ScriptJob
        Write-Host "[INFO: $Script] Script invoked on $($Session.ComputerName)" -ForegroundColor Green
    }
    
    $Complete = @()
    $TotalJobs = $Jobs.count
    $IncompleteJobs = @()
    while ($Complete.Count -lt $TotalJobs) {
        for ($i = 0; $i -lt $Jobs.count; $i++) {
            # Job States: https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.jobstate?view=powershellsdk-7.4.0
            if ($Jobs[$i].State -eq "Completed" -and $Complete -notcontains $Jobs[$i].Location) {
                $Jobs[$i] | Receive-Job | Out-File "$Out\$($Jobs[$i].Location).$Extension" -Encoding utf8
                Write-Host "[INFO: $Script] Script completed on $($Jobs[$i].Location) logged to $Extension" -ForegroundColor Green
                $Complete += $($Jobs[$i].Location)
            }
            elseif ($Jobs[$i].State -eq "Running" -and $Complete -notcontains $Jobs[$i].Location){
                $IncompleteJobs += $Jobs[$i]
            }
            elseif (($Jobs[$i].State -eq "Failed" -or $Jobs[$i].State -eq "Blocked" -or $Jobs[$i].State -eq "Disconnected" -or $Jobs[$i].State -eq "Stopped" -or $Jobs[$i].State -eq "Suspended") -and $Complete -notcontains $Jobs[$i].Location){
                Write-Host "[ERROR: $Script] Script $($Jobs[$i].State) on $($Jobs[$i].Location)" -ForegroundColor Red
                $Complete += $($Jobs[$i].Location)
            }
        }
        if ($IncompleteJobs.Count -ge 1){
            $Jobs = $IncompleteJobs
            $IncompleteJobs = @()
            Start-Sleep -Milliseconds 25
        }
    }
    Get-Job | Remove-Job -Force
}
if ($Sessions.Count -eq 0 -and !$Connect) {
    Write-Host "[ERROR] No sessions" -ForegroundColor Red
}
if ($Script -eq '' -and !$Connect) {
    Write-Host "[ERROR] No script" -ForegroundColor Red
}
if ($Out -eq '' -and !$Connect) {
    Write-Host "[ERROR] No output directory" -ForegroundColor Red
}