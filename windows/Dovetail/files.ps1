$files = @(
    "C:\Windows\System32\utilman.exe",
    "C:\Windows\System32\sethc.exe",
    "C:\Windows\System32\osk.exe",
    "C:\Windows\System32\narrator.exe",
    "C:\Windows\System32\magnify.exe"
)

foreach ($file in $files) {
    if (Test-Path $file) {        
        $directory = Split-Path $file -Parent
        $randomString = -join ((65..90) + (97..122) | Get-Random -Count 15 | ForEach-Object { [char]$_ })
        $newFilename = "$randomString.exe"
        $newPath = Join-Path $directory $newFilename
        
        $takeownResult = takeown.exe /F $file /A
        if ($LASTEXITCODE -ne 0) {
            continue
        }
        
        $icaclsResult = icacls.exe $file /grant Administrators:F
        if ($LASTEXITCODE -ne 0) {
            continue
        }
                
        try {
            $acl = Get-Acl $file
            $owner = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $acl.SetOwner($owner)
            Set-Acl -Path $file -AclObject $acl -ErrorAction SilentlyContinue
            
            Rename-Item -Path $file -NewName $newFilename -Force -ErrorAction Stop
            Write-Output "Renamed '$file' to '$newFilename'"
        }
        catch {
            try {
                $moveCommand = "cmd.exe /c move /Y `"$file`" `"$newPath`""
                $moveResult = Invoke-Expression $moveCommand
                Write-Output "Moved '$file' to '$newFilename'"
            }
            catch {
                continue
            }
        }
    }
    else {
        continue
    }
}

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
