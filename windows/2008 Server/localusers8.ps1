$outputFile = [System.IO.Path]::Combine([Environment]::GetFolderPath("MyDocuments"), "LocalUserPasswords.txt")


function Generate-RandomPassword {
    param (
        [int]$length = 12
    )
    $chars = @(
        ([char[]](48..57)) + 
        ([char[]](65..90)) + 
        ([char[]](97..122)) + 
        ('!', '@', '#', '$', '%', '^', '&', '*', '-', '_')
    ) | ForEach-Object { $_ }
    -join ((1..$length) | ForEach-Object { $chars | Get-Random })
}

Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True" | ForEach-Object {
    if ($_.Name -ne "Administrator" -and $_.Disabled -eq $false) {
        try {
            $username = $_.Name
            $password = Generate-RandomPassword
            net user $username $password
        }catch{
            Write-Host "Failed to change password for $username" -ForegroundColor Red
        }
        try{
            "$username,$password" | Out-File -FilePath $outputFile -Append -Encoding UTF8
        }catch{
            Write-Host "Failed to write password in file for $username" -ForegroundColor Red
        }
        
    }
}