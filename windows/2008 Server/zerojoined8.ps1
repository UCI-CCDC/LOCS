
if (Test-Path -Path "C:\zerojoined.txt") {
    Write-Host "Zerojoined already run..."
    return
}


Write-Host "Disabling Print Spooler service..."
try {
    Set-Service -Name "Spooler" -StartupType Disabled
    Stop-Service -Name "Spooler" -Force
    Write-Host "Print Spooler service disabled." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Print Spooler service: $_" -ForegroundColor Red
}


$Error.Clear()
$ErrorActionPreference = "Continue"


Write-Output "Disable PHP Functions"

$php = Get-ChildItem -Path "C:\" -Filter "php.exe" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {

        & $_.FullName --ini | Out-String
    }

$ConfigFiles = @()
foreach ($OutputLine in ($php -split "`r`n")) {
    if ($OutputLine -match 'Loaded') {
        $ConfigFiles += ($OutputLine -split "\s{9}")[1]
    }
}

$ConfigString_DisableFuncs = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
$ConfigString_FileUploads  = "file_uploads=off"

foreach ($ConfigFile in $ConfigFiles) {
    if (Test-Path $ConfigFile) {
        Add-Content $ConfigFile $ConfigString_DisableFuncs
        Add-Content $ConfigFile $ConfigString_FileUploads
        Write-Output "$Env:ComputerName [INFO] PHP functions disabled in $ConfigFile"
    }
    else {
        Write-Output "$Env:ComputerName [WARNING] Could not find file: $ConfigFile"
    }
}


Write-Host "Resetting IIS to apply changes..."
try {
    iisreset
}
catch {
    Write-Host "Failed to reset IIS or IIS not installed: $_"
}


if ($Error[0]) {
    Write-Output "ERRORS`n" 
    foreach ($err in $Error) {
        Write-Output $err
    }
}


New-Item -Path "C:\zerojoined.txt" -ItemType File -Force
