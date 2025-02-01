$params = @{
    Name        = 'hacker1'
    Password    =  Read-Host "Enter password" -AsSecureString
}
New-LocalUser @params

Add-LocalGroupMember -Group "Administrators" -Member "hacker1"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "hacker1"