@echo off
powershell -Command "Start-Process powershell -ArgumentList 'Get-Content C:\Users\HayZun\Desktop\script.ps1 | PowerShell.exe -noprofile -' -Verb RunAs"