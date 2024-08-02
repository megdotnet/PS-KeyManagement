
$passwordPath = Join-Path (Split-Path $profile) SecretStore.vault.credential

function Test-SecretStore {

    #defaults
    $diag = @{
        SecretManagementModule = $false
        SecretStoreModule = $false  
        SecretKeyImport = $false
        KeyTest = $false
        VaultTest = $false
        AllTestsPassed = $true
      }

    try {
        Import-Module -Name Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        $diag['SecretManagementModule'] = $true
    }
    catch {
        $diag["AllTestsPassed"] = $false
    }

    try {
        Import-Module -Name Microsoft.PowerShell.SecretStore -ErrorAction Stop
        $diag['SecretStoreModule'] = $true
    }
    catch { 
        $diag["AllTestsPassed"] = $false
    }

    try { 
        $pass = Import-Clixml $passwordPath
        $diag['SecretKeyImport'] = $true
    }
    catch {
        $pass = $null
        $diag["AllTestsPassed"] = $false
    }

    try {
        Unlock-SecretStore -Password $pass
        $diag["KeyTest"] = $true
    }
    catch {
        $diag["AllTestsPassed"] = $false
    }

    $vaults = Get-SecretVault
    if ($vaults) {
        $diag["VaultTest"] = $true
    }
    else {
        $diag["AllTestsPassed"] = $false
    }
    

    return $diag
}

function Show-Diagnostics {
    param (
        $SecretManagementModule,
        $SecretStoreModule,  
        $SecretKeyImport,
        $KeyTest,
        $VaultTest,
        $AllTestsPassed
    )

    $vaults = Get-SecretVault
    $VaultCount = $vaults.count
    $DefaultVault = $($vaults | Select-Object | Where-Object  { $_.IsDefault -eq $True }).Name

    if ($SecretManagementModule) {
        $SecretManagementColor = "Green"
        $SecretManagementMessage = "Installed"
    }
    else {
        $SecretManagementColor = "Red"
        $SecretManagementMessage = "Not Installed"
    }

    if ($SecretStoreModule) {
        $SecretStoretColor = "Green"
        $SecretStoreMessage = "Installed"
    }
    else {
        $SecretStoretColor = "Red"
        $SecretStoreMessage = "Not Installed"
    }

    if ($SecretKeyImport) {
        $StoreKeyColor = "Green"
        $StoreKeyMessage = "Installed"
    }
    else {
        $StoreKeyColor = "Red"
        $StoreKeyMessage = "Not Installed"
    }

    if ($KeyTest) {
        $KeyTestColor = "Green"
        $KeyTestMessage = "Passed"
    }
    else {
        $KeyTestColor = "Red"
        $KeyTestMessage = "Failed"
    }

    if ($VaultCount -ge 1) {
        $VaultCountColor = "Green" 
    }
    else {
        $VaultCountColor = "Red"
    }

    if ($DefaultVault) {
        $VaultColor = "Green"
        $VaultMessage = $DefaultVault
    }
    else {
        $VaultColor = "Red"
        $VaultMessage = "none"
    }



    
    Clear-Host
    Write-Host "`n"
    Write-Host "Secret Management:  " -NoNewline; Write-Host -ForegroundColor $SecretManagementColor $SecretManagementMessage
    Write-Host "     Secret Store:  " -NoNewline; Write-Host -ForegroundColor $SecretStoretColor $SecretStoreMessage
    Write-Host " Store Key Import:  " -NoNewline; Write-Host -ForegroundColor $StoreKeyColor $StoreKeyMessage
    Write-Host "         Key Test:  " -NoNewline; Write-Host -ForegroundColor $KeyTestColor $KeyTestMessage
    Write-Host "       Num Vaults:  " -NoNewline; Write-Host -ForegroundColor $VaultCountColor $vaultcount
    Write-Host "    Default Vault:  " -NoNewline; Write-Host -ForegroundColor $VaultColor $VaultMessage
    Write-Host "`n[F]ix issues"
    $selection = Read-Host -Prompt "-->"
            switch ($selection) {
                'f'  { Invoke-GFKeyFixes @diag }
                'diag'  { $diag = Test-SecretStore; Get-Diagnostics @diag }
                }
}

function Get-GFSecretInfo {
    # This function returns a list of all secrets
    
    $i = 0
    $list = Get-SecretInfo | Select-Object *
    if ($list) {
        $output=@()
        foreach ($secret in $list) {
            $secret_username = (Get-Secret $secret.Name).UserName
            $output += [PSCustomObject]@{
                Index = $i
                "Secret Name" = $secret.Name
                Username = $secret_username
                Description = $secret.Metadata["Description"]
                Updated = $secret.Metadata["Updated"]
                VaultName = $secret.VaultName
            }
            $i ++
        }
    }
    else {
        $output = "`nNo secrets in vault."
    }
    
    return $output
}

function New-GFSecret {
    
    $secret_name = Read-Host -Prompt "`nSecret Name"
    $secret_username = Read-Host -Prompt "Username"
    $secret_password = Read-Host -AsSecureString -Prompt "Password"    
    $secret_description = Read-Host -Prompt "Description"

    $cred = New-Object System.Management.Automation.PSCredential ($secret_username, $secret_password)
    $date = Get-Date
    
    Set-Secret -Name $secret_name -Metadata @{Description = $secret_description; Updated = $date} -Secret $cred
    Write-Host "`nSecret $secret_name created.`n"
    pause
}

function Set-GFSecret {
    param (
        $list
    )

    $i = Read-Host -Prompt "Index to modify"
    $secret_name = $list[$i].'Secret Name'
    $secret_username = $list[$i].Username
    $secret_description = $list[$i].Description
    $secret_updated = $list[$i].Updated
    
    Write-Host "`nSecret Name:  $secret_name"
    Write-Host "   Username:  $secret_username"
    Write-Host "Description:  $secret_description"
    Write-Host "    Updated:  $secret_updated"
    $p = Read-Host -Prompt "`nModify this secret? (y/n)"

    if ($p -eq "y") {
        $secret_password = Read-Host -AsSecureString -Prompt "New Password"
    }

    $cred = New-Object System.Management.Automation.PSCredential ($secret_username, $secret_password)
    $date = Get-Date
    
    Set-Secret -Name $secret_name -Metadata @{Description = $secret_description; Updated = $date} -Secret $cred
    Write-Host "`nSecret $secret_name updated.`n"
    pause

}

function Get-GFSecretPassword {
    param (
        $list 
    )
    $i = Read-Host -Prompt "Select index"
    $secret_name = $list[$i].'Secret Name'
    $secret_username = $list[$i].Username

    $secret_password = (Get-Secret $secret_name).Password
    Set-Clipboard -Value $($secret_password | ConvertFrom-SecureString -AsPlainText)
    Write-Host "`nSecret Name:  $secret_name"
    Write-Host "   Username:  $secret_username"
    Write-Host "Password copied to clipboard.`n"
    pause
}

function Remove-GFSecret {
    param (
        $list
    )
    $i = Read-Host -Prompt "Select index"
    $secret_name = $list[$i].'Secret Name'
    $secret_username = $list[$i].Username
    $secret_description = $list[$i].Description
    $secret_updated = $list[$i].Updated
    $secret_vault = $list[$i].VaultName
    
    Write-Host "`nSecret Name:  $secret_name"
    Write-Host "   Username:  $secret_username"
    Write-Host "Description:  $secret_description"
    Write-Host "    Updated:  $secret_updated"
    
    Remove-Secret -Name $secret_name -Vault $secret_vault -Confirm
    # Write-Host "`nUser $user delete.`n"
    pause
    
}

function Set-VaultKey {
    Write-Host "`nEnter a password for the vault."
    $key = Read-Host -Prompt "-->" -AsSecureString
    $key
}

function Invoke-GFKeyFixes {
    param (
        $SecretManagementModule,
        $SecretStoreModule,  
        $SecretKeyImport,
        $KeyTest,
        $VaultTest,
        $AllTestsPassed
    )

    if (-not $SecretManagementModule) {
        Get-PackageProvider Nuget -ForceBootstrap
        Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery -Force
    }
    
    if (-not $SecretStoreModule) {
        Get-PackageProvider Nuget -ForceBootstrap
        Install-Module Microsoft.PowerShell.SecretStore -Repository PSGallery -Force 
    }

    if (-not $SecretKeyImport) { 
        Write-Host "`nPlease create a master password for the key store.`n"
        Write-Host "This key will be stored in a hashed file on the local machine"
        Write-Host "and will only be readable by the Windows user account that"
        Write-Host "created it. (i.e. your currently logged in account)`n"
        Write-Host "Please remember to store this password in a safe place.`n"
        $secret_key = Read-Host -Prompt "New Password" -AsSecureString

        $secret_key | Export-Clixml $passwordPath

        Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout (60*60) -Interaction None -Password $secret_key -Confirm:$false
    }

    if (-not $VaultTest) {
        Write-Host "`nPlease enter a name for your secret vault.`n"
        $vault_name = Read-Host -Prompt "Vault Name" 
        Register-SecretVault -Name $vault_name -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
    }
}


#
#####  ENTRY POINT  #####
#


$diag = Test-SecretStore

if ($diag["AllTestsPassed"]) {
    do {
        Clear-Host
        $list = Get-GFSecretInfo
        $list | Format-Table
        Write-Host "`n[N]ew [U]pdate [P]ass [D]elete [diag] [Q]uit"
        $selection = Read-Host -Prompt "-->"
        switch ($selection) {
            'n'  { New-GFSecret }
            'u'  { Set-GFSecret $list }
            'd'  { Remove-GFSecret $list }
            'p'  { Get-GFSecretPassword $list }
            'diag'  { $diag = Test-SecretStore; Show-Diagnostics @diag }
            }
    }
    until ($selection -eq "q")
}
else {
    Show-Diagnostics @diag
}
