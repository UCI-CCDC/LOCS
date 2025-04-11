
$archiveDestinationPath = "C:\LogArchives" 

$xamppBaseDir = "C:\xampp"


$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$archiveFileName = "LogArchive_$($env:COMPUTERNAME)_$timestamp.zip"
$archiveFullPath = Join-Path -Path $archiveDestinationPath -ChildPath $archiveFileName

$tempDir = Join-Path -Path $env:TEMP -ChildPath "LogStaging_$timestamp"

$eventLogDir = "C:\Windows\System32\winevt\Logs"

$iisLogDir = Join-Path -Path $env:SystemDrive -ChildPath "inetpub\logs\LogFiles"
$xamppApacheLogDir = Join-Path -Path $xamppBaseDir -ChildPath "apache\logs"
$xamppMySqlLogDir = Join-Path -Path $xamppBaseDir -ChildPath "mysql\data" 
$xamppPhpLogPath = Join-Path -Path $xamppBaseDir -ChildPath "php\logs"
$firewallLogPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\LogFiles\Firewall"
$dnsLogPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\dns" 
$xamppFilezillaLogDir = Join-Path -Path $xamppBaseDir -ChildPath "FileZillaFTP\Logs"
$FilezillaDir = Join-Path -path $env:SystemDrive -ChildPath "Program Files\FileZilla Server\Logs"
$FilezillaDir2 = Join-Path -path $env:SystemDrive -ChildPath "Program Files (x86)\FileZilla Server\Logs"
$xamppWordpress = Join-Path -Path $xamppBaseDir -ChildPath "htdocs\wordpress\wp-content"
$hmailDir = Join-Path -path $env:SystemDrive -ChildPath "Program Files\hmailServer\Logs"
$hmailDir2 = Join-Path -path $env:SystemDrive -ChildPath "Program Files (x86)\hmailServer\Logs"
$mailEnableDir = Join-Path -path $env:SystemDrive -ChildPath "Program Files\Mail Enable\Logging"
$mailEnableDir2 = Join-Path -path $env:SystemDrive -ChildPath "Program Files (x86)\Mail Enable\Logging"


$allLogs = @{
    iisLogDir         = $iisLogDir
    xamppApacheLogDir = $xamppApacheLogDir
    xamppMySqlLogDir  = $xamppMySqlLogDir
    xamppPhpLogPath   = $xamppPhpLogPath
    firewallLogPath   = $firewallLogPath
    dnsLogPath        = $dnsLogPath
    xamppFilezillaLogDir = $xamppFilezillaLogDir
    filezillaDir      = $filezillaDir
    filezillaDir2     = $filezillaDir2
    wordpressXampp    = $xamppWordpress
    hmailDir          = $hmailDir
    hmailDir2         = $hmailDir2
    mailEnableDir     = $mailEnableDir
    mailEnableDir2    = $mailEnableDir2


}

$mysqlBasePaths = @(
    "${env:ProgramData}\MySQL"
)

foreach ($basePath in $mysqlBasePaths) {
    if (Test-Path $basePath) {
        Get-ChildItem -Path $basePath -Directory | ForEach-Object {
            if ($_.Name -like "MySQL Server*") {
                $dataDir = Join-Path -Path $_.FullName -ChildPath "Data"
                if (Test-Path $dataDir) {
                    $keyName = "soloMySqlLogDir"
                    $allLogs[$keyName] = $dataDir
                }
            }
        }
    }
}

$orangehrmBasePaths = @(
    "${xamppBaseDir}\htdocs"
)

foreach ($basePath in $orangehrmBasePaths) {
    if (Test-Path $basePath) {
        Get-ChildItem -Path $basePath -Directory | ForEach-Object {
            if ($_.Name -like "orangehrm*") {
                $dataDir = Join-Path -Path $_.FullName -ChildPath "src\log"
                if (Test-Path $dataDir) {
                    $keyName = "orangehrm"
                    $allLogs[$keyName] = $dataDir
                }
            }
        }
    }
}


Write-Host "Starting Log Archival Script..."

if (-not (Test-Path -Path $archiveDestinationPath -PathType Container)) {
    Write-Host "Creating destination directory: $archiveDestinationPath"
    try {
        New-Item -Path $archiveDestinationPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to create destination directory '$archiveDestinationPath'. Error: $($_.Exception.Message)"
        Exit 1
    }
}

Write-Host "Creating temporary staging directory: $tempDir"
try {
    New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Failed to create temporary directory '$tempDir'. Error: $($_.Exception.Message)"
    Exit 1
}


Write-Host "Exporting Event Viewer Logs..."
if (Test-Path -Path $eventLogDir -PathType Container) {
    $eventDest = Join-Path -Path $tempDir -ChildPath "EventLogs"
    Write-Host "  - Found Event logs at '$eventLogDir'. Copying to '$eventDest'..."
    try {
        Copy-Item -Path $eventLogDir -Destination $eventDest -Recurse -Force -ErrorAction Stop
        Write-Host "    Successfully copied Event logs."
    } catch {
        Write-Warning "    Failed to copy Event logs from '$eventLogDir'. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "  - Event log directory not found: '$eventLogDir'. Skipping."
}


foreach ($logEntry in $allLogs.GetEnumerator()) {
    $name = $logEntry.Key
    $logPath = $logEntry.Value

    Write-Host "Copying logs for: $name"
    if (Test-Path -Path $logPath -PathType Container) {
        $dest = Join-Path -Path $tempDir -ChildPath "$name"
        Write-Host "  - Found logs at '$logPath'. Copying to '$dest'..."
        try {
            Copy-Item -Path $logPath -Destination $dest -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully copied logs."
        } catch {
            Write-Warning "Failed to copy logs from '$logPath'. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Log directory not found: '$logPath'. Skipping."
    }
}

Compress-Archive -Path "$tempDir\*" -DestinationPath $archiveFullPath -Force -ErrorAction Stop

Write-Host "Successfully created archive: $archiveFullPath"
# --- Cleanup ---
Write-Host "Cleaning up temporary directory: $tempDir"
try {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction Stop
    Write-Host "Cleanup successful."
} catch {
    Write-Warning "Failed to remove temporary directory '$tempDir'. Manual cleanup may be required. Error: $($_.Exception.Message)"
}

Write-Host "Log Archival Script Finished."
