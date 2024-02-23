@echo off
powershell -Command "Start-Process powershell -ArgumentList ('Get-Content ' + $env:USERPROFILE + '\Desktop\script.ps1' + ' | PowerShell.exe -noprofile -') -Verb RunAs"