param (
    [string]$FilePath
)

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show((Get-Content $FilePath), 'Message', 'OK', 'Information')