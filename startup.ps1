# Description: Script PowerShell pour créer un utilisateur ansible et configurer l'auto-login
# Auteur: Durieux Paul
# TODO:
# - créer le Github Actions pour exécuter le script
# - trouver un moyen d'exécuter le script avec une commande unique
# - Set-executionpolicy unrestricted -force -scope CurrentUser

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


# vérifier que l'utisateur n'existe pas
function User-Exists {
    param (
        [string]$username
    )
    $user = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    return $user -ne $null
}

# modifier le nom de l'utilisateur et son mdp
# TODO en fonction de la langue du système, le groupe Administrateurs peut être Administrators (à vérifier)
# renommer le dossier de l'utilisateur en ansible
function configureAnsibleUser {
    param(
        [string]$username,
        [string]$password
    )
    Rename-LocalUser -Name "$env:UserName" -NewName "ansible"
    Set-LocalUser -Name "ansible" -Password (ConvertTo-SecureString "ansible" -AsPlainText -Force)
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

    #Attends que les autres opérations soient terminées avant de redémarrer
    Start-Sleep -Seconds 10

    # Étape 4 : Redémarrage de l'ordinateur
    Restart-Computer
}

#Configurer WinRM pour autoriser les connexions distantes
function configureWinRM {
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
    Restart-Service WinRM
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    # Autoriser le trafic entrant sur le port 5986
    netsh advfirewall firewall add rule Profile=Domain name="Autoriser WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow

}

#Enable le ping avec le pare-feu
function enablePing {
    New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -Direction Inbound -Action Allow -Enabled True
}

#TODO start at a scheduled task
function displayMessage {
    param (
        [string]$message,
        [string]$title
    )
    [System.Windows.Forms.MessageBox]::Show($message, $title, 'OK', 'Information')
}

function retrieveIp {
    #get the ip address interface ethernet
    $ip = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq "Ethernet" -and $_.AddressFamily -eq "IPv4" }

    #if ip starts with 169.254, then it's a link-local address
    if ($ip.IPAddress.StartsWith("169.254")) {
        #get the ip address interface wifi
        $ip = Get-NetIPAddress | Where-Object { $_.InterfaceAlias -eq "Wi-Fi" -and $_.AddressFamily -eq "IPv4" }
    }
    return $ip.IPAddress
}

# Ajouter une tâche planifiée pour exécuter une commande au démarrage de la session
function addStartupTask {
    param (
        [string]$command
    )
    $taskName = "StartupTask"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command $command"
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -RunLevel Highest
}


# Définition de la fonction principale
function Main {
    setExecutionPolicy
    createAnsibleFolder
    autoLogin
    configureWinRM
    # Attendre que le service WinRM soit en cours d'exécution
    while ((Get-Service -Name WinRM).Status -ne "Running") {
        # Attendre 1 seconde avant de vérifier à nouveau
        Start-Sleep -Seconds 10
    }
    enablePing
    configureAnsibleUser
    displayMessage "L'ordinateur est prêt à être utilisé. L'adresse IP est : $(retrieveIp)" "Configuration terminée"
}

# Appel de la fonction principale
Main