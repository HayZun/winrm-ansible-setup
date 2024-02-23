@echo off
set "FilePath=%~1"
powershell.exe -WindowStyle Hidden -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show((Get-Content '%FilePath%'), 'Message', 'OK', 'Information')"