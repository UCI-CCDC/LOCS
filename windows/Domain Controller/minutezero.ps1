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
