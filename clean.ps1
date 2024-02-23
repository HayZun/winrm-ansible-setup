# Supprimer l'auto-login
# TODO : remetre l'éxécution du script en mode Restricted
function remove-auto-login {
    # Définition des paramètres
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $AutoAdminLogon = "AutoAdminLogon"
    $DefaultUserName = "DefaultUserName"
    $DefaultPassword = "DefaultPassword"
    $DefaultDomainName = "DefaultDomainName"

    # Étape 1 : Suppression de la clé AutoAdminLogon
    Remove-ItemProperty -Path $RegPath -Name $AutoAdminLogon -Force | Out-Null

    # Étape 2 : Suppression du nom d'utilisateur par défaut
    Remove-ItemProperty -Path $RegPath -Name $DefaultUserName -Force | Out-Null

    # Étape 3 : Suppression du mot de passe par défaut
    Remove-ItemProperty -Path $RegPath -Name $DefaultPassword -Force | Out-Null

    # Étape 4 : Suppression du domaine par défaut
    Remove-ItemProperty -Path $RegPath -Name $DefaultDomainName -Force | Out-Null

    # Étape 5 : Redémarrage de l'ordinateur
    Restart-Computer
}

# Supprimer la feature OpenSSH
function Remove-OpenSSH {
    Remove-WindowsCapability -Online -Name OpenSSH.Client
    Remove-WindowsCapability -Online -Name OpenSSH.Server
}

# enlever la configuration de WinRM
function Unconfigure-WinRM {
    Disable-PSRemoting -Force
    Remove-Item WSMan:\localhost\Client\TrustedHosts -Force
    Restart-Service WinRM
    # Supprimer la règle de pare-feu
    netsh advfirewall firewall delete rule name="Autoriser WinRM HTTPS"
}