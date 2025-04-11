$secureBackupPath = "C:\Users\Administrator\Documents\dns"

if (!(Test-Path -Path $secureBackupPath)) {
    New-Item -Path $secureBackupPath -ItemType Directory -Force
}

# Get all DNS zones on the server
$zones = Get-DnsServerZone

foreach ($zone in $zones) {
    $zoneName = $zone.ZoneName
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFileName = "${zoneName}_backup_$timestamp.dns"
    $tempFilePath = "C:\Windows\System32\dns\$backupFileName"
    $finalFilePath = Join-Path $secureBackupPath $backupFileName

    Export-DnsServerZone -Name $zoneName -FileName $backupFileName

    Move-Item -Path $tempFilePath -Destination $finalFilePath -Force

    Write-Host "Backed up zone '$zoneName' to '$finalFilePath'"
}

Write-Host "All DNS zones backed up successfully."

