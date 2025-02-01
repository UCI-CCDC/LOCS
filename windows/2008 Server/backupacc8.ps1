$username = "hacker1"
$password = Read-Host "Enter password"  

$user = [ADSI]"WinNT://$env:COMPUTERNAME"
$newUser = $user.Create("User", $username)
$newUser.SetPassword($password)
$newUser.SetInfo()

$groups = @("Administrators", "Remote Desktop Users")

foreach ($group in $groups) {
    $groupObj = [ADSI]"WinNT://$env:COMPUTERNAME/$group,group"
    $groupObj.Add("WinNT://$env:COMPUTERNAME/$username,user")
}