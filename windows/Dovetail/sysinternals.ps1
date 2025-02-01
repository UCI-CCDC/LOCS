[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'

$sysinternalsUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$destinationPath = "$env:USERPROFILE\Downloads\SysinternalsSuite.zip"

Invoke-WebRequest -Uri $sysinternalsUrl -OutFile $destinationPath

Expand-Archive -Path $destinationPath -DestinationPath "$env:USERPROFILE\Downloads\SysinternalsSuite"

Write-Host "Sysinternals Suite downloaded and extracted to $env:USERPROFILE\Downloads\SysinternalsSuite"
