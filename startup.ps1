# Fonction pour créer un dossier ansible dans C:\
function CreateAnsibleFolder {
    $path = "C:\ansible"
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory | Out-Null
    }
}

# Fonction pour définir la stratégie d'exécution
function SetExecutionPolicy {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
}

# Fonction pour configurer l'utilisateur Ansible
function ConfigureAnsibleUser {
    param(
        [string]$username,
        [string]$password
    )
    Rename-LocalUser -Name "$env:UserName" -NewName "ansible"
    Set-LocalUser -Name $username -Password (ConvertTo-SecureString $password -AsPlainText -Force)
}

# Fonction pour configurer l'auto-login
function AutoLogin {
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $Properties = @{
        AutoAdminLogon    = "1"
        DefaultUserName   = "ansible"
        DefaultPassword   = "ansible"
        DefaultDomainName = "localhost"
    }
    foreach ($prop in $Properties.GetEnumerator()) {
        New-ItemProperty -Path $RegPath -Name $prop.Key -Value $prop.Value -PropertyType String -Force | Out-Null
    }
}

# Fonction pour configurer WinRM
function ConfigureWinRM {
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Set-NetConnectionProfile -NetworkCategory Private
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
    Restart-Service WinRM
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    netsh advfirewall firewall add rule Profile=Domain name="Allow WinRM HTTPS" dir=in localport=5985 protocol=TCP action=allow
}

# Fonction pour autoriser le ping
function EnablePing {
    New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -Direction Inbound -Action Allow -Enabled True
}

# Fonction pour récupérer l'adresse IP
function RetrieveIP {
    $ip = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -like "Ethernet*" -and $_.AddressFamily -eq "IPv4" }
    if ($null -eq $ip -or $ip.IPAddress.StartsWith("169.254")) {
        $ip = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq "Wi-Fi" -and $_.AddressFamily -eq "IPv4" }
    }
    return $ip.IPAddress
}

# Fonction pour créer le fichier message.txt
function CreateMessageTxt {
    $ip = RetrieveIP
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    $model = (Get-WmiObject -Class Win32_ComputerSystem).Model
    $message = @"
Informations nécessaires pour la configuration de WinRM :
Adresse IP : $ip
Fabricant : $manufacturer
Modele : $model
La configuration de WinRM est terminee. Vous pouvez maintenant administrer cet hote a distance avec Ansible.
"@
    $message | Out-File -FilePath "C:\ansible\message.txt" -Force -Encoding utf8
}

# Fonction pour ajouter une tâche planifiée
function AddStartupTask {
    param (
        [string]$argument
    )
    $taskName = "AnsibleCanDeploy"
    $action = New-ScheduledTaskAction -Execute "C:\ansible\messagebox.bat" -Argument $argument 
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $triggerSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $triggerSettings
}

# Fonction pour déplacer le script messagebox.bat dans le dossier C:\ansible
function MoveMessageBoxScript {
    $directoryInstall = "$env:USERPROFILE\Desktop\winrm-ansible-setup\winrm-ansible-setup-main"
    Move-Item -Path "$directoryInstall\messagebox.bat" -Destination "C:\ansible\messagebox.bat" -Force
}

# Fonction principale
function Main {
    CreateAnsibleFolder
    CreateMessageTxt
    SetExecutionPolicy
    AutoLogin
    ConfigureWinRM
    EnablePing
    AddStartupTask -Argument "C:\ansible\message.txt"
    ConfigureAnsibleUser -username "ansible" -password "ansible"
    MoveMessageBoxScript
    Restart-Computer -Force
}

# Appel de la fonction principale
Main