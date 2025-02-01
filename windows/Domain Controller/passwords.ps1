function Generate-RandomPassword {
    $length = 10
    $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
    $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
    $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
    $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
    $all     = $upper + $lower + $numbers + $special
    $passwordArray = @(
        ($upper   | Get-Random -Count 1) +
        ($lower   | Get-Random -Count 1) +
        ($numbers | Get-Random -Count 1) +
        ($special | Get-Random -Count 1) +
        ($all     | Get-Random -Count ($length - 4))
    )
    $passwordArray    = $passwordArray -join ''
    $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
    $finalPassword = $shuffledPassword -replace '\s', ''
    return $finalPassword
}
$outputFilePath = "C:\Users\Administrator\Documents\passwords_output.txt"
Import-Module ActiveDirectory
$excludedGroups = @("Domain Admins", "Enterprise Admins")
$excludedUsers = foreach ($group in $excludedGroups) {
    Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
}
$excludedUsers = $excludedUsers | Select-Object -Unique
$excludedUsers += @("Administrator", "krbtgt")
$users = Get-ADUser -Filter * | Where-Object {
    ($_.SamAccountName -notin $excludedUsers) -and
    ($_.SamAccountName -ne "Administrator") -and
    ($_.SamAccountName -ne "krbtgt") 
}
Set-Content -Path $outputFilePath -Value "Username,Password"
$GroupUserMap = @{}

foreach ($user in $users) {
    try {
        $newPassword    = Generate-RandomPassword
        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePassword -Reset
        Write-Host "$($user.SamAccountName),$newPassword" -ForegroundColor Green
        $outputLine = "$($user.SamAccountName),$newPassword"
        Add-Content -Path $outputFilePath -Value $outputLine
        
        $usersgroups = Get-ADPrincipalGroupMembership -Identity $user | Select-Object -ExpandProperty Name
        
        if ($usersgroups) {
            foreach ($groupName in $usersgroups) {
                if(!($GroupUserMap.ContainsKey($groupName))) {
                    $GroupUserMap[$groupName] = New-Object System.Collections.ArrayList
                }
                
                if (($user.SamAccountName -ne "Guest") -and ($user.SamAccountName -ne "DefaultAccount")){
                    $null = $GroupUserMap[$groupName].Add([PSCustomObject]@{
                        User     = $user.SamAccountName
                        Password = $newPassword
                    })
                }
            }
        }
    } 
    catch {
        Write-Error "Failed to set password for user $($user.SamAccountName): $_"
    }
}

Write-Host "`n=== GROUP MEMBERSHIP & PASSWORDS ===" -ForegroundColor Cyan

foreach ($groupName in $GroupUserMap.Keys) {
    
    if ($GroupUserMap[$groupName].Count -gt 0){
        Add-Content -Path $outputFilePath -Value ""
        Write-Host "`nGroup: $groupName" -ForegroundColor Yellow
        Add-Content -Path $outputFilePath -Value "`n`nGroup: $groupName"
        
        foreach ($userEntry in $GroupUserMap[$groupName]) {
            Write-Host "$($userEntry.User),$($userEntry.Password)"
            Add-Content -Path $outputFilePath -Value "$($userEntry.User),$($userEntry.Password)"
        }
    }
}

Write-Host "Password rotation complete. Output saved to $outputFilePath" -ForegroundColor Cyan
