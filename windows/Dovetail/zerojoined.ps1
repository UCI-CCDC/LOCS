if (Test-Path -Path "C:\zerojoined.txt") {
    Write-Host "Zerojoined already run..."
    return
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

$php = Get-ChildItem -Path "C:\" -Filter "php.exe" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { & $_.FullName --ini | Out-String }

$ConfigFiles = @()
foreach ($OutputLine in ($php -split "`r`n")) {
    if ($OutputLine -match 'Loaded') {
        $ConfigFiles += ($OutputLine -split "\s{9}")[1]
    }
}

$ConfigString_DisableFuncs = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
$ConfigString_FileUploads  = "file_uploads=off"

foreach ($ConfigFile in $ConfigFiles) {
    Add-Content $ConfigFile $ConfigString_DisableFuncs
    Add-Content $ConfigFile $ConfigString_FileUploads
    Write-Output "$Env:ComputerName [INFO] PHP functions disabled in $ConfigFile"
}

iisreset
if ($Error[0]) {
    Write-Output "`n#########################"
    Write-Output "#        ERRORS         #"
    Write-Output "#########################`n"
    foreach ($err in $Error) {
        Write-Output $err
    }
}


# Make a new file as a flag
New-Item -Path "C:\zerojoined.txt" -ItemType File 

