# Configuration de WinRM pour Ansible

Ce script PowerShell automatise le processus de configuration de WinRM sur des machines Windows afin de les préparer à être gérées à distance avec Ansible.
## Utilisation 
1. **Téléchargement et exécution du script :** 

Pour télécharger le script et l'exécuter, utilisez la commande suivante dans PowerShell :

```powershell
Invoke-WebRequest 'https://github.com/HayZun/winrm-ansible-setup/archive/main.zip' -OutFile "$env:USERPROFILE\Desktop\winrm-ansible-setup.zip" -UseBasicParsing ; Expand-Archive -Path "$env:USERPROFILE\Desktop\winrm-ansible-setup.zip" -DestinationPath "$env:USERPROFILE\Desktop\winrm-ansible-setup" -Force ; Start-Process -FilePath "$env:USERPROFILE\Desktop\winrm-ansible-setup\winrm-ansible-setup-main\runme.bat" -Verb RunAs ; Remove-Item -Path "$env:USERPROFILE\Desktop\winrm-ansible-setup.zip" -Force
``` 
2. **Exécution du script :** 

Le script télécharge l'archive contenant les fichiers de configuration nécessaires, l'extrait et exécute le fichier `runme.bat` pour configurer WinRM. Assurez-vous d'avoir les privilèges administratifs nécessaires pour exécuter la commande. 