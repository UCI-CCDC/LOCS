if (Test-Path -Path "C:\zerojoined.txt") {
    Write-Host "Zerojoined already run..."
    
}

Set-Service -Name "Spooler" -StartupType Disabled
Stop-Service -Name "Spooler" -Force

try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "SMBv1 disabled via Set-SmbServerConfiguration." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable SMBv1 using Set-SmbServerConfiguration (not available on some OS versions)."
}

$Error.Clear()
$ErrorActionPreference = "Continue"

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



# DC
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    # Do Nothing
}



if ($Error[0]) {
    Write-Output "#        ERRORS         #"

    foreach ($err in $error) {
        Write-Output $err
    }
}

# Make a new file as a flag
New-Item -Path "C:\zerojoined.txt" -ItemType File 