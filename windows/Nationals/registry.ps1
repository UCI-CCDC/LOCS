$userToAudit = "Everyone"

$rights = `
    [System.Security.AccessControl.RegistryRights]::QueryValue -bor `
    [System.Security.AccessControl.RegistryRights]::SetValue -bor `
    [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor `
    [System.Security.AccessControl.RegistryRights]::Delete

$inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
$propFlags = [System.Security.AccessControl.PropagationFlags]::None

$auditFlags = [System.Security.AccessControl.AuditFlags]::Success

$registryRoots = @(
    "HKLM:\",
    "HKCU:\",
    "HKCR:\",
    "HKU:\",
    "HKCC:\"
)

foreach ($root in $registryRoots) {
    try {
        Write-Host "Processing $root..."

        $acl = Get-Acl -Path $root

        $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
            $userToAudit,
            $rights,
            $inheritFlags,
            $propFlags,
            $auditFlags
        )
        $acl.AddAuditRule($rule)
        Set-Acl -Path $root -AclObject $acl

    } catch {
        Write-Warning "Failed to update"
    }
}
