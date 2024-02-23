@echo off
set "FilePath=%~1"
powershell.exe -WindowStyle Hidden -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show((Get-Content -Path '%FilePath%' -Raw), 'Message', 'OK', 'Information')"