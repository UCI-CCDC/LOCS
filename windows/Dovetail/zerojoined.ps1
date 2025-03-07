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


# Make a new file as a flag
New-Item -Path "C:\zerojoined.txt" -ItemType File 

