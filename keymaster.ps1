
$passwordPath = Join-Path (Split-Path $profile) SecretStore.vault.credential
try { 
    $pass = Import-Clixml $passwordPath
}
catch {
    $pass = $null
}

try {
    Import-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Stop
    $SecretManagement = "Installed"
    $smcolor = "Green"
}
catch {
    $SecretManagement = "Not Installed" 
    $smcolor = "Red"
}

try {
    Import-Module -Name Microsoft.PowerShell.SecretStore -ErrorAction Stop
    $SecretStore = "Installed"
    $storecolor = "Green"
}
catch { 
    $SecretStore = "Non Installed"
    $storecolor = "Red"
}

if (Test-Path -Path $passwordPath) {
    $pwpath = "Found"
    $pwcolor = "Green"
}
else {
    $pwpath = "Not Found"
    $pwcolor = "Red"
}

$keytest = ""
try {
    Unlock-SecretStore -Password $pass
    $keytest = "Success"
    $ktcolor = "Green"
}
catch {
    $keytest = "Fail"
    $ktcolor = "Red"
}

$vaults = Get-SecretVault
$vaultcount = $vaults.count
$defaultvault = $($vaults | Select-Object | Where-Object  { $_.IsDefault -eq $True }).Name


Clear-Host
Write-Host "`n"
Write-Host "Secret Management:  " -NoNewline; Write-Host -ForegroundColor $smcolor $SecretManagement
Write-Host "     Secret Store:  " -NoNewline; Write-Host -ForegroundColor $storecolor $SecretStore
Write-Host "    Password Path:  " -NoNewline; Write-Host -ForegroundColor $pwcolor $pwpath
Write-Host "         Key Test:  " -NoNewline; Write-Host -ForegroundColor $ktcolor $keytest
Write-Host "       Num Vaults:  $vaultcount"
Write-Host "    Default Vault:  $defaultvault"
# Write-Host ""

function Get-GFSecretInfo {
    # This function returns a list of all secrets
    $output=@()
    $i = 0
    $list = Get-SecretInfo | Select-Object *
    foreach ($secret in $list) {
        $output += [PSCustomObject]@{
            Index = $i
            Name = $secret.Name
            Type = $secret.Type
            Vault = $secret.VaultName
            Description = $secret.Metadata["Description"]
            Updated = $secret.Metadata["Updated"]
        }
        $i ++
    }
    return $output
}

function Set-GFSecret {
    # This function will create or update an existing secret
    param (
        $user
    )

    if (-not $user) {
        $user = Read-Host -Prompt "`nNew Username"
        
        $pwprompt = "New Password"
        $message = "created."
    }
    else { 
        $pwprompt = "New password for $user"
        $message = "updated."
    }

    $password = Read-Host -AsSecureString -Prompt $pwprompt
    $cred = New-Object System.Management.Automation.PSCredential ($user, $password)

    $description = Read-Host -Prompt "Description"
    $date = Get-Date

    set-Secret -Name $user -Metadata @{Description = $description; Updated = $date} -Secret $cred
    Write-Host "`nUser $user $message`n"
    pause
    clear-host 
    Get-GFSecretInfo | Format-Table
}

function Remove-GFSecret {
    param (
        $user, 
        $vault
    )
    Remove-Secret -Name $user -Vault $vault
    Write-Host "`nUser $user delete.`n"
    pause
    clear-host 
    Get-GFSecretInfo | Format-Table
}
function Get-GFSecret {
    
    param(
    [switch] $update,
    [switch] $delete
    )

    Clear-Host 
    do {
        $list  = Get-GFSecretInfo
        $list | format-table 
        $set = Read-Host -prompt "-->"

        if ($set -eq "q") {
            $exit = $True 
        }
        else {
            $exit = $false
        }

        try {
            $user = $list[$set].Name
            $vault = $list[$set].Vault
        }
        catch {
            write-host "try again"
        }

        if ($update) {
            $uprompt = Read-Host -Prompt "Update user: $user`n(y/n)"
            if ($uprompt -eq "y") {
                Set-GFSecret $user
                $exit = $True
            }
        }
        elseif ($delete) {
            $uprompt = Read-Host -Prompt "Delete user: $user`n(y/n)"
            if ($uprompt -eq "y") {
                Remove-GFSecret $user $vault
                $exit = $True
            }
        }
    }
    until ($exit)

}

function Set-VaultKey {
    Write-Host "`nEnter a password for the vault."
    $key = Read-Host -Prompt "-->" -AsSecureString
    $key
}

do {
    Write-Host "`n[I]nstall [S]etVaultKey New[V]ault"
    Write-Host "[V]iew [C]reate [U]pdate [D]elete [Q]uit"
    $selection = Read-Host -Prompt "-->"
    switch ($selection) {
        'v'  { Clear-Host; Get-GFSecretInfo | format-table } 
        'c'  { Set-GFSecret }
        'u'  { Get-GFSecret -update }
        'd'  { Get-GFSecret -delete }
        }
}
until ($selection -eq "q")