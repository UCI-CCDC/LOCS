function Generate-RandomPassword {
    $length = 10

    [char[]]$upper   = (65..90)  | ForEach-Object { [char]$_ }  # A-Z
    [char[]]$lower   = (97..122) | ForEach-Object { [char]$_ }  # a-z
    [char[]]$numbers = (48..57)  | ForEach-Object { [char]$_ }  # 0-9

    $specialString   = '!@#$%&*()-_=+[]{}<>?' 
    [char[]]$special = $specialString.ToCharArray()

    $all = $upper + $lower + $numbers + $special

    $pick = @()
    $pick += ($upper   | Get-Random)
    $pick += ($lower   | Get-Random)
    $pick += ($numbers | Get-Random)
    $pick += ($special | Get-Random)

    $remaining = $length - 4
    if ($remaining -gt 0) {
        $shuffledAll = $all | Sort-Object { Get-Random }
        $pick += $shuffledAll[0..($remaining - 1)]
    }

    $final = $pick | Sort-Object { Get-Random }

    return -join $final
}


$rootDSE   = [ADSI]"LDAP://RootDSE"
$defaultNC = $rootDSE.defaultNamingContext


function Get-SamAccountNameFromDN {
    param([string]$dn)
    $obj  = [ADSI]"LDAP://$dn"
    $raw  = $obj.Properties["sAMAccountName"][0]
    if ($raw) { return $raw.Trim().ToLower() }
    return $null
}


$outputFilePath = "C:\Users\Administrator\Documents\passwords_output.txt"


$excludedGroups = @("Domain Admins", "Enterprise Admins")

function Get-GroupMembers-ADSI {
    param([string]$groupName)
    $groupDN  = "CN=$groupName,CN=Users,$defaultNC"
    $groupObj = [ADSI]"LDAP://$groupDN"

    $memberDNs = @($groupObj.Properties["member"])
    if (-not $memberDNs) { return @() }

    foreach ($dn in $memberDNs) {
        Get-SamAccountNameFromDN $dn
    }
}


$excludedUsers = foreach ($g in $excludedGroups) {
    Get-GroupMembers-ADSI $g
}


$additionalExcludes = @("Administrator","krbtgt","wasabi","hacker1","guest") |
    ForEach-Object { $_.Trim().ToLower() }

$excludedUsers += $additionalExcludes

$excludedUsers = $excludedUsers | Where-Object { $_ } | Select-Object -Unique

Write-Host "Excluded accounts are:"
$excludedUsers | ForEach-Object { Write-Host " - $_" }


Write-Host "Collecting all user objects via ADSI..."
$searcher              = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
$searcher.Filter       = "(&(objectCategory=person)(objectClass=user))"
$searcher.PageSize     = 1000
$searcher.SearchScope  = "Subtree"

$results       = $searcher.FindAll()
$usersToChange = @()

foreach ($res in $results) {
    $userObj = $res.GetDirectoryEntry()
    $rawSam  = $userObj.Properties["sAMAccountName"].Value

    if ($rawSam) {
        $sam = $rawSam.Trim().ToLower()
    }
    else {
        continue 
    }

    if ($excludedUsers -contains $sam) {
        Write-Host "Skipping excluded user: $sam" -ForegroundColor Cyan
        continue
    }

    Write-Host "Including user: $sam"
    $usersToChange += $userObj
}

Write-Host "Total user accounts found (excluding): $($usersToChange.Count)"


Set-Content -Path $outputFilePath -Value "Username,Password"

$GroupUserMap = @{}

function Get-GroupNameFromDN {
    param([string]$dn)
    try {
        $groupADSI = [ADSI]"LDAP://$dn"
        $gSam = $groupADSI.Properties["sAMAccountName"][0]
        if (-not $gSam) {
            if ($dn -match '^CN=([^,]+),') {
                return $matches[1]
            }
        }
        return $gSam
    }
    catch {
        if ($dn -match '^CN=([^,]+),') {
            return $matches[1]
        }
        return $dn
    }
}

foreach ($userObj in $usersToChange) {
    $rawSam = $userObj.Properties["sAMAccountName"].Value
    $sam    = $rawSam.Trim().ToLower()

    try {
        $newPassword = Generate-RandomPassword

        $userObj.psbase.Invoke("SetPassword", $newPassword)

        # $userObj.Properties["pwdLastSet"].Value = 0

        $userObj.SetInfo()

        Write-Host "$sam,$newPassword" -ForegroundColor Green
        Add-Content -Path $outputFilePath -Value "$sam,$newPassword"

        $groupsDN = $userObj.Properties["memberOf"]
        if ($groupsDN) {
            foreach ($groupDN in $groupsDN) {
                $groupName = Get-GroupNameFromDN $groupDN
                if (-not $groupName) { continue }

                if (-not $GroupUserMap.ContainsKey($groupName)) {
                    $GroupUserMap[$groupName] = New-Object System.Collections.ArrayList
                }

                $null = $GroupUserMap[$groupName].Add([PSCustomObject]@{
                    User     = $sam
                    Password = $newPassword
                })
            }
        }
    }
    catch {
        Write-Host "Failed to set password for user $sam: $_" -ForegroundColor Red
    }
}

###############################################################################
# 10) Done with password resets. Now let's print out group-wise breakdown.
###############################################################################
Write-Host "`n=== GROUP MEMBERSHIP & PASSWORDS ===" -ForegroundColor Cyan

foreach ($groupName in $GroupUserMap.Keys) {
    Write-Host "`nGroup: $groupName" -ForegroundColor Yellow
    Add-Content -Path $outputFilePath -Value "`nGroup: $groupName"

    # For each user in that group
    foreach ($userEntry in $GroupUserMap[$groupName]) {
        # $userEntry has .User and .Password
        Write-Host "$($userEntry.User),$($userEntry.Password)"
        Add-Content -Path $outputFilePath -Value "$($userEntry.User),$($userEntry.Password)"
    }
}

Write-Host "`nPassword rotation complete. Output saved to $outputFilePath" -ForegroundColor Cyan
