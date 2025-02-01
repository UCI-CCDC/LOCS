<#
.SYNOPSIS
    Hardening script adapted to work with Windows Server 2008 / 2008 R2.
#>


Write-Host "Removing unauthorized users from privileged groups..." -ForegroundColor Yellow

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Please install RSAT for Windows Server 2008/2008R2 to use AD cmdlets."
    return
}
else {
    Import-Module ActiveDirectory
}

$excludedSamAccountNames = @(
    "Administrator",
    "Domain Admins",
    "Enterprise Admins"
)

$groups = @("Domain Admins", "Enterprise Admins", "Administrators")

foreach ($group in $groups) {
    try {
        $members = Get-ADGroupMember -Identity $group | Where-Object {
            $excludedSamAccountNames -notcontains $_.SamAccountName
        }

        foreach ($member in $members) {
            Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
            Write-Host "Removed $($member.SamAccountName) from $group." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to remove members from $group: $_" -ForegroundColor Red
    }
}


Write-Host "Enabling Kerberos Pre-authentication for all users..." -ForegroundColor Yellow

$users = Get-ADUser -Filter * -Properties userAccountControl

foreach ($user in $users) {
    $uac = $user.userAccountControl
    if ($uac -band 4194304) {
        $newUac = $uac -bxor 4194304
        try {
            Set-ADUser -Identity $user.SamAccountName -Replace @{ userAccountControl = $newUac }
            Write-Host "Kerberos Pre-authentication enabled for user $($user.SamAccountName)." -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to enable Kerberos Pre-authentication for user $($user.SamAccountName). $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Kerberos Pre-auth already enabled for user $($user.SamAccountName)."
    }
}
Write-Host "Kerberos Pre-authentication step completed." -ForegroundColor Cyan


Write-Host "Disabling Guest account..." -ForegroundColor Yellow
try {
    $guestAccount = Get-ADUser -Identity "Guest" -Properties userAccountControl
    if ($guestAccount) {
        $uac = $guestAccount.userAccountControl
        if (-not ($uac -band 2)) {
            $uac = $uac -bor 2
            Set-ADUser -Identity $guestAccount.SamAccountName -Replace @{ userAccountControl = $uac }
            Write-Host "Guest account has been disabled." -ForegroundColor Green
        }
        else {
            Write-Host "Guest account was already disabled." -ForegroundColor Green
        }
    }
}
catch {
    Write-Host "Failed to disable Guest account: $_" -ForegroundColor Red
}


Write-Host "Disabling Print Spooler service..." -ForegroundColor Yellow
try {
    Stop-Service -Name "Spooler" -ErrorAction Stop
    Set-Service -Name "Spooler" -StartupType Disabled
    Write-Host "Print Spooler service has been disabled." -ForegroundColor Green
}
catch {
    Write-Host "Failed to disable Print Spooler service: $_" -ForegroundColor Red
}


Write-Host "Applying Zerologon mitigation..." -ForegroundColor Yellow
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    Write-Host "FullSecureChannelProtection enabled." -ForegroundColor Green

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $regName = "vulnerablechannelallowlist"

    if (Test-Path -Path "$regPath\$regName") {
        Remove-ItemProperty -Path $regPath -Name $regName -Force | Out-Null
        Write-Host "vulnerablechannelallowlist removed." -ForegroundColor Green
    }
    else {
        Write-Host "vulnerablechannelallowlist does not exist, no action needed." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Failed to apply Zerologon mitigation: $_" -ForegroundColor Red
}


Write-Host "Applying noPAC mitigation..." -ForegroundColor Yellow
try {
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $root = $domainObj.GetDirectoryEntry()

    $root."ms-DS-MachineAccountQuota" = 0
    $root.CommitChanges()

    Write-Host "ms-DS-MachineAccountQuota set to 0." -ForegroundColor Green
}
catch {
    Write-Host "Failed to apply noPAC mitigation: $_" -ForegroundColor Red
}

Write-Host "All tasks completed." -ForegroundColor Cyan
