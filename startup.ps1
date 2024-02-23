# Description: Script PowerShell pour créer un utilisateur ansible et configurer l'auto-login
# Auteur: Durieux Paul

# créer le dossier temporaire ansible dans le C:\ansible
function createAnsibleFolder {
    $path = "C:\ansible"
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory
    }
}

#Set-executionpolicy unrestricted -force -scope CurrentUser
function setExecutionPolicy {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
}

# modifier le nom de l'utilisateur et son mdp
function configureAnsibleUser {
    param(
        [string]$username,
        [string]$password
    )
    Rename-LocalUser -Name "$env:UserName" -NewName "ansible"
    Set-LocalUser -Name $username -Password (ConvertTo-SecureString $password -AsPlainText -Force)
}

# Fonction pour configurer l'auto-login
function autoLogin {
    # Définition des paramètres
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $AutoAdminLogon = "AutoAdminLogon"
    $DefaultUserName = "DefaultUserName"
    $DefaultPassword = "DefaultPassword"
    $DefaultDomainName = "DefaultDomainName"

    # Étape 1 : Création de la clé AutoAdminLogon avec la valeur 1
    New-ItemProperty -Path $RegPath -Name $AutoAdminLogon -Value "1" -PropertyType String -Force | Out-Null

    # Étape 2 : Définition du nom d'utilisateur par défaut
    New-ItemProperty -Path $RegPath -Name $DefaultUserName -Value "ansible" -PropertyType String -Force | Out-Null

    # Étape 3 : Définition du mot de passe par défaut
    New-ItemProperty -Path $RegPath -Name $DefaultPassword -Value "ansible" -PropertyType String -Force | Out-Null

    # Étape 4 : Définition du domaine par défaut
    New-ItemProperty -Path $RegPath -Name $DefaultDomainName -Value "localhost" -PropertyType String -Force | Out-Null
}
    

#Configurer WinRM pour autoriser les connexions distantes
function configureWinRM {
    # Definir le profil de connexion sur privé
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Set-NetConnectionProfile -NetworkCategory Private
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
    Restart-Service WinRM
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    # Autoriser le trafic entrant sur le port 5986
    netsh advfirewall firewall add rule Profile=Domain name="Autoriser WinRM HTTPS" dir=in localport=5985 protocol=TCP action=allow

}

#Enable le ping avec le pare-feu
function enablePing {
    New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -Direction Inbound -Action Allow -Enabled True
}

function retrieveIp {
    # Get the IP address of the Ethernet interface
    $ip = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -like "Ethernet*" -and $_.AddressFamily -eq "IPv4" }

    # Check if the IP is null or starts with 169.254 (link-local address)
    if ($null -eq $ip -or $ip.IPAddress.StartsWith("169.254")) {
        # Get the IP address of the Wi-Fi interface
        $ip = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq "Wi-Fi" -and $_.AddressFamily -eq "IPv4" }
    }

    # Return the IP address
    return $ip.IPAddress
}

# Création du fichier message.txt
function createMessageTxt {
    $ip = retrieveIp
    $manufacter = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer
    $model = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
    $message = "Informations necessaires pour la configuration :`n`nAdresse IP : $ip`nFabricant : $manufacter`nModèle : $model`n`n"
    $message | Out-File -FilePath "C:\ansible\message.txt" -Force -Encoding utf8
}

# Ajouter une tâche planifiée pour exécuter une commande au déverrouillage de la session
function addStartupTask {
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

# Déplacer le script messagebox.ps1 dans le dossier C:\ansible
function moveMessageBoxScript {
    $directoryInstall = "$env:USERPROFILE\Desktop\winrm-ansible-setup\winrm-ansible-setup-main"
    Move-Item -Path "$directoryInstall\messagebox.bat" -Destination "C:\ansible\messagebox.bat" -Force
}

# Définition de la fonction principale
function Main {
    createAnsibleFolder
    createMessageTxt
    setExecutionPolicy
    autoLogin
    configureWinRM
    enablePing
    # fix mappage error
    addStartupTask -Argument "C:\ansible\message.txt"
    configureAnsibleUser -username "ansible" -password "ansible"
    moveMessageBoxScript
    # wait for the task to be created
    Restart-Computer -Force
}

# Appel de la fonction principale
Main