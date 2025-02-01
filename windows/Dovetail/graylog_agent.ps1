$installerUrl = "https://github.com/Graylog2/collector-sidecar/releases/download/1.0.0/graylog_sidecar_installer_1.0.0-1.exe"

$installerPath = "C:\Users\Administrator\Documents\graylog_sidecar_installer_1.0.0.exe"

$serverUrl = "http://10.100.1.59:9090/api/"
$apiToken = "ohkqpt5ikl7sg0p3qk53o87o9cjfbaaht9kfrnhc0shfgrep4co"

$configFilePath = "C:\Program Files\Graylog\sidecar\sidecar.yml"

$sidecarExePath = "C:\Program Files\Graylog\sidecar\graylog-sidecar.exe"

if (-Not (Test-Path -Path $installerPath)) {
    Write-Host "Installer not found locally. Downloading from GitHub..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath 
}

if (-Not (Test-Path -Path $installerPath)) {
    Write-Error "Installer could not be downloaded from $installerUrl. Please check the URL and your network connection."
    exit
}

Write-Host "Installing Graylog Sidecar silently..."
$process = Start-Process -FilePath $installerPath -ArgumentList "/S", "-SERVERURL=$serverUrl", "-APITOKEN=$apiToken" -PassThru -Wait

if ($process.ExitCode -eq 0) {
    Write-Host "Graylog Sidecar installation completed successfully."
} else {
    Write-Error "Graylog Sidecar installation failed with exit code: $($process.ExitCode)."
    exit
}

if (-Not (Test-Path -Path $sidecarExePath)) {
    Write-Error "Graylog Sidecar executable not found at $sidecarExePath."
    exit
}

Write-Host "Installing Graylog Sidecar service..."
Start-Process -FilePath $sidecarExePath -ArgumentList "-service install" -Wait

Write-Host "Starting Graylog Sidecar service..."
Start-Process -FilePath $sidecarExePath -ArgumentList "-service start" -Wait

$serviceName = "Graylog Sidecar"
$serviceFound = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $serviceFound) {
    Write-Error "Graylog Sidecar service was not started successfully."
    exit
}

Write-Host "Graylog Sidecar service started successfully."

Write-Host "Stopping Graylog Sidecar service to update the configuration file..."
Stop-Service -Name $serviceName -Force

Write-Host "Updating Graylog Sidecar configuration..."
if (Test-Path -Path $configFilePath) {
    $configContent = Get-Content -Path $configFilePath

    $configContent = $configContent -replace 'node_name:.*', 'node_name: ""'

    Set-Content -Path $configFilePath -Value $configContent -Force

    Write-Host "Graylog Sidecar configuration updated successfully."
} else {
    Write-Error "Configuration file not found at $configFilePath"
    exit
}

Write-Host "Restarting Graylog Sidecar service..."
Start-Service -Name $serviceName

Write-Host "Graylog Sidecar service restarted successfully."
