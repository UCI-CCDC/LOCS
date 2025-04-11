# NO SPACES BETWEEN IPS
$localsubnet=""
$domain_controller_ip=""
$user_ips=""

if (Test-Path -Path "C:\zerojoined.txt") {
    Write-Host "Zerojoined already run..."
}


# SMB
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "SMBv1 disabled via Set-SmbServerConfiguration." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable SMBv1 using Set-SmbServerConfiguration (not available on some OS versions)."
}


# Print Spooler
Set-Service -Name "Spooler" -StartupType Disabled
Stop-Service -Name "Spooler" -Force

$Error.Clear()
$ErrorActionPreference = "Continue"


# Local Admin passwords
if (!(Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")) {
    $length = 12
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    $adminpassword = -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    $adminpassword += "!"
    
    net user Administrator "$adminpassword"
    
    Write-Output "LOCALADMINPASSWORD: $env:COMPUTERNAME,$adminpassword"
}


# Local User passwords
if (!(Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'")) {
    # $outputFile = "C:\Users\Administrator\Documents\passwords_output.txt"
    Write-Output $env:COMPUTERNAME

    function Generate-RandomPassword {
        $length = 10
        $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
        $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
        $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
        $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
        $all     = $upper + $lower + $numbers + $special
        $passwordArray = @(
            ($upper   | Get-Random -Count 1) +
            ($lower   | Get-Random -Count 1) +
            ($numbers | Get-Random -Count 1) +
            ($special | Get-Random -Count 1) +
            ($all     | Get-Random -Count ($length - 4))
        )
        $passwordArray    = $passwordArray -join ''
        $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
        $finalPassword = $shuffledPassword -replace '\s', ''
        return $finalPassword
    }

    Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True" | ForEach-Object {
        if ($_.Name -ne "Administrator" -and $_.Disabled -eq $false -and $_.Name -ne "hacker1") {
            try {
                $username = $_.Name
                $password = Generate-RandomPassword
                net user $username $password
            }catch{
                Write-Host "Failed to change password for $username" -ForegroundColor Red
            }
            try{
                # "$username,$password" | Out-File -FilePath $outputFile -Append -Encoding UTF8
                Write-Output "$username,$password"
            }catch{
                Write-Host "Failed to write password in file for $username" -ForegroundColor Red
            }
            
        }
    }
}
else {
    $hostname = $env:computername
    Write-Host "$hostname is a Domain Controller..."
}

# Domain-User Passwords
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    function Generate-RandomPassword {
        $length = 10
        $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
        $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
        $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
        $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
        $all     = $upper + $lower + $numbers + $special
        $passwordArray = @(
            ($upper   | Get-Random -Count 1) +
            ($lower   | Get-Random -Count 1) +
            ($numbers | Get-Random -Count 1) +
            ($special | Get-Random -Count 1) +
            ($all     | Get-Random -Count ($length - 4))
        )
        $passwordArray    = $passwordArray -join ''
        $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
        $finalPassword = $shuffledPassword -replace '\s', ''
        return $finalPassword
    }
    # $outputFilePath = "C:\Users\Administrator\Documents\passwords_output.txt"
    Write-Output $env:ComputerName
    Import-Module ActiveDirectory
    $excludedGroups = @("Domain Admins", "Enterprise Admins")
    $excludedUsers = foreach ($group in $excludedGroups) {
        Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
    }
    $excludedUsers = $excludedUsers | Select-Object -Unique
    $excludedUsers += @("Administrator", "krbtgt")
    $users = Get-ADUser -Filter * | Where-Object {
        ($_.SamAccountName -notin $excludedUsers) -and
        ($_.SamAccountName -ne "Administrator") -and
        ($_.SamAccountName -ne "krbtgt") 
    }
    # Set-Content -Path $outputFilePath -Value "Username,Password"
    Write-Output "Username,Password"
    $GroupUserMap = @{}

    foreach ($user in $users) {
        try {
            $newPassword    = Generate-RandomPassword
            $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
            Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset
            Write-Host "$($user.SamAccountName),$newPassword" -ForegroundColor Green
            $outputLine = "$($user.SamAccountName),$newPassword"
            # Add-Content -Path $outputFilePath -Value $outputLine
            Write-Output $outputLine
            
            $usersgroups = Get-ADPrincipalGroupMembership -Identity $user | Select-Object -ExpandProperty Name
            
            if ($usersgroups) {
                foreach ($groupName in $usersgroups) {
                    if(!($GroupUserMap.ContainsKey($groupName))) {
                        $GroupUserMap[$groupName] = New-Object System.Collections.ArrayList
                    }
                    
                    if (($user.SamAccountName -ne "Guest") -and ($user.SamAccountName -ne "DefaultAccount")){
                        $null = $GroupUserMap[$groupName].Add([PSCustomObject]@{
                            User     = $user.SamAccountName
                            Password = $newPassword
                        })
                    }
                }
            }
        } 
        catch {
            Write-Error "Failed to set password for user $($user.SamAccountName): $_"
        }
    }

    Write-Host "`n=== GROUP MEMBERSHIP & PASSWORDS ===" -ForegroundColor Cyan
    Write-Output "`n=== GROUP MEMBERSHIP & PASSWORDS ==="
    foreach ($groupName in $GroupUserMap.Keys) {
        
        if ($GroupUserMap[$groupName].Count -gt 0){
            # Add-Content -Path $outputFilePath -Value ""
            Write-Host "`nGroup: $groupName" -ForegroundColor Yellow
            Write-Output "`nGroup: $groupName"
            Write-Output "$($userEntry.User),$($userEntry.Password)"
            # Add-Content -Path $outputFilePath -Value "`n`nGroup: $groupName"
            
            foreach ($userEntry in $GroupUserMap[$groupName]) {
                Write-Host "$($userEntry.User),$($userEntry.Password)"
                Write-Output "$($userEntry.User),$($userEntry.Password)"
                # Add-Content -Path $outputFilePath -Value "$($userEntry.User),$($userEntry.Password)"
            }
        }
    }

    # Write-Host "Password rotation complete. Output saved to $outputFilePath" -ForegroundColor Cyan
}


# DC Minute Zero
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    $groups = @("Domain Admins", "Enterprise Admins", "Administrators", "DnsAdmins", "Group Policy Creator Owners", "Schema Admins", "Key Admins", "Enterprise Key Admins")

    foreach ($group in $groups) {
        $excludedSamAccountNames = @("Administrator", "Domain Admins", "Enterprise Admins")

        $members = Get-ADGroupMember -Identity $group | Where-Object {
            $excludedSamAccountNames -notcontains $_.SamAccountName
        }

        foreach ($member in $members) {
            try {
                Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
                Write-Host "Removed $($member.SamAccountName) from $group." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to remove group member $($member.SamAccountName) from $group."
            }
        }
    }


    try {
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
        Write-Host "Kerberos Pre-authentication enabled for applicable users." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable Kerberos Pre-authentication: $_" -ForegroundColor Red
    }

    try {
        $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
        Disable-ADAccount -Identity $guestAccount.SamAccountName
        Write-Host "Guest account has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to disable Guest account."
    }

    try {
        Stop-Service -Name "Spooler" -ErrorAction Stop
        Set-Service -Name "Spooler" -StartupType Disabled
        Write-Host "Print Spooler service has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to disable Print Spooler service: $_" -ForegroundColor Red
    }

    try {
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
        Write-Host "FullSecureChannelProtection enabled." -ForegroundColor Green

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        $regName = "vulnerablechannelallowlist"
        if (Test-Path -Path "$regPath\$regName") {
            Remove-ItemProperty -Path $regPath -Name $regName -Force | Out-Null
            Write-Host "vulnerablechannelallowlist removed." -ForegroundColor Green
        } else {
            Write-Host "vulnerablechannelallowlist does not exist, no action needed." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Failed to apply Zerologon mitigation: $_" -ForegroundColor Red
    }

    try {
        Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota" = "0" } | Out-Null
        Write-Host "ms-DS-MachineAccountQuota set to 0." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to apply noPac mitigation: $_" -ForegroundColor Red
    }
}

# PHP
$ConfigFiles = Get-ChildItem -Path "C:\xampp", "C:\inetpub" -Filter "php.ini" -Recurse -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty FullName

if (-not $ConfigFiles) {
    Write-Output "No php.ini files found in the specified folders."
}
else {
    $ConfigString_DisableFuncs = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
    $ConfigString_FileUploads        = "file_uploads=off"
    $ConfigString_TrackErrors        = "track_errors = off"
    $ConfigString_HtmlErrors         = "html_errors = off"
    $ConfigString_MaxExecutionTime   = "max_execution_time = 3"
    $ConfigString_DisplayErrors      = "display_errors = off"
    $ConfigString_ShortOpenTag       = "short_open_tag = off"
    $ConfigString_SessionCookieHTTPO = "session.cookie_httponly = 1"
    $ConfigString_SessionUseCookies  = "session.use_only_cookies = 1"
    $ConfigString_SessionCookieSecure= "session.cookie_secure = 1"
    $ConfigString_ExposePhp          = "expose_php = off"
    $ConfigString_MagicQuotesGpc     = "magic_quotes_gpc = off"
    $ConfigString_AllowUrlFopen      = "allow_url_fopen = off"
    $ConfigString_AllowUrlInclude    = "allow_url_include = off"
    $ConfigString_RegisterGlobals    = "register_globals = off"
    $ConfigStrings = @(
        $ConfigString_DisableFuncs,
        $ConfigString_FileUploads,
        $ConfigString_TrackErrors,
        $ConfigString_HtmlErrors,
        $ConfigString_MaxExecutionTime,
        $ConfigString_DisplayErrors,
        $ConfigString_ShortOpenTag,
        $ConfigString_SessionCookieHTTPO,
        $ConfigString_SessionUseCookies,
        $ConfigString_SessionCookieSecure,
        $ConfigString_ExposePhp,
        $ConfigString_MagicQuotesGpc,
        $ConfigString_AllowUrlFopen,
        $ConfigString_AllowUrlInclude,
        $ConfigString_RegisterGlobals
    )

    foreach ($ConfigFile in $ConfigFiles) {
        foreach ($Config in $ConfigStrings) {
            Add-Content -Path $ConfigFile -Value $Config
        }
        Write-Output "$Env:ComputerName [INFO] Configuration updated in $ConfigFile"
    }

    iisreset
    if (Test-Path "C:\xampp\xampp_stop.exe") {
        & "C:\xampp\xampp_stop.exe"
        Start-Sleep -Seconds 5
        & "C:\xampp\xampp_start.exe"
    } else {
        Write-Output "XAMPP installation not found. Skipping XAMPP restart."
    }
}


# Files Permissions
takeown /F "C:\Windows\System32\cmd.exe" /A
icacls "C:\Windows\System32\cmd.exe" /reset

takeown /F "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /A
icacls "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /reset

takeown /F "C:\Windows\regedit.exe" /A
icacls "C:\Windows\regedit.exe" /reset

takeown /F "C:\Windows\System32\mmc.exe" /A
icacls "C:\Windows\System32\mmc.exe" /reset

takeown /F "C:\Windows\System32\wscript.exe" /A
icacls "C:\Windows\System32\wscript.exe" /reset

takeown /F "C:\Windows\System32\cscript.exe" /A
icacls "C:\Windows\System32\cscript.exe" /reset


# Firewall
netsh a s allp state off
netsh a s allp firewallpolicy "allowinbound,blockoutbound"
netsh a f s r n=all new enable=no
netsh a f a r n=ICMP dir=in a=allow prot=ICMPv4
netsh a f a r n=DNS_OUT dir=out a=allow prot=UDP remoteport=53 remoteip="10.120.0.53,$domain_controller_ip"
netsh a f a r n=RDP dir=in a=allow prot=TCP localport=3389 remoteip=$user_ips
netsh a f a r n=CCS_OUT dir=out a=allow program="C:\CCS\CCSClient.exe"

netsh a f a r n=MYSQL dir=out a=allow prot=TCP remoteport=3306 remoteip=$localsubnet
netsh a f a r n=POSTGRES dir=out a=allow prot=TCP remoteport=5432 remoteip=$localsubnet
netsh a f a r n=MONGO dir=out a=allow prot=TCP remoteport=27017 remoteip=$localsubnet
netsh a f a r n=MYSQL dir=in a=allow prot=TCP localport=3306 remoteip=$localsubnet
netsh a f a r n=POSTGRES dir=in a=allow prot=TCP localport=5432 remoteip=$localsubnet
netsh a f a r n=MONGO dir=in a=allow prot=TCP localport=27017 remoteip=$localsubnet

netsh a f s r group="Active Directory Domain Services" new enable=yes
$localsubnet = ($localsubnet.Split(',')).Trim()
Get-NetFirewallRule -DisplayGroup "Active Directory Domain Services" -Direction Inbound | Set-NetFirewallRule -RemoteAddress $localsubnet
Get-NetFirewallRule -DisplayGroup "Active Directory Domain Services" -Direction Outbound | Set-NetFirewallRule -RemoteAddress $localsubnet

netsh a f a r n=TO_DC dir=out a=allow prot=TCP remoteip=$domain_controller_ip
netsh a f a r n=TO_DC dir=out a=allow prot=UDP remoteip=$domain_controller_ip

# DC
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    netsh a f a r n=DNS_IN dir=in a=allow prot=UDP localport=53
}

netsh a s allp firewallpolicy "blockinbound,blockoutbound"

Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 10000

# Windows Defender
if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "Windows Defender exists."
    try {
        $mpPrefs = Get-MpPreference

        if ($mpPrefs.ExclusionProcess) { 
            Remove-MpPreference -ExclusionProcess $mpPrefs.ExclusionProcess 
        }
        if ($mpPrefs.ExclusionPath) { 
            Remove-MpPreference -ExclusionPath $mpPrefs.ExclusionPath 
        }
        if ($mpPrefs.ExclusionExtension) { 
            Remove-MpPreference -ExclusionExtension $mpPrefs.ExclusionExtension 
        }

        Set-MpPreference -DisableRealtimeMonitoring $false
    } catch {
        Write-Output "Error configuring Windows Defender: $_"
    }
} else {
    Write-Host "Windows Defender does not exist." -ForegroundColor Red
}

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] PTH Mitigation complete"

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] Set Defender options" 

$addMpPrefCmd = Get-Command Add-MpPreference -ErrorAction SilentlyContinue
if ($addMpPrefCmd.Parameters.ContainsKey("AttackSurfaceReductionRules_Ids")) {
    # Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Win32 API calls from Office macro
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Use advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null
    # Block use of copied or impersonated system tools
    Add-MpPreference -AttackSurfaceReductionRules_Ids C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB -AttackSurfaceReductionRules_Actions Enabled | Out-Null

    Write-Output "$Env:ComputerName [INFO] Defender Attack Surface Reduction rules enabled" 
    ForEach ($ExcludedASR in (Get-MpPreference).AttackSurfaceReductionOnlyExclusions) {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null
    }
}
else {
    Write-Output "$Env:ComputerName [INFO] Old defender version detected, skipping ASR rules" 
}
ForEach ($ExcludedExt in (Get-MpPreference).ExclusionExtension) {
    Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null
}
ForEach ($ExcludedIp in (Get-MpPreference).ExclusionIpAddress) {
    Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null
}
ForEach ($ExcludedDir in (Get-MpPreference).ExclusionPath) {
    Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null
}
ForEach ($ExcludedProc in (Get-MpPreference).ExclusionProcess) {
    Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null
}

# UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
Write-Output "$Env:ComputerName [INFO] UAC enabled"


if ($Error[0]) {
    Write-Output "#        ERRORS         #"

    foreach ($err in $error) {
        Write-Output $err
    }
}

# Powershell History
Clear-History
Clear-Content -Path (Get-PSReadlineOption).HistorySavePath -Force

# Make a new file as a flag
New-Item -Path "C:\zerojoined.txt" -ItemType File 