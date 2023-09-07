@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Exfiltration.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '02373c76-f078-447e-8e9c-dfd32bcf6c5f'

# Author of this module
Author = 'Original Author Matthew Graeber'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'Powerscript Exfiltration Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = 'Get-VaultCredential.ps1xml'

# Functions to export from this module
FunctionsToExport = '*'

# List of all files packaged with this module
FileList = 'Exfiltration.psm1', 'Exfiltration.psd1', 'Get-TimedScreenshot.ps1', 'Out-Minidump.ps1',
           'Get-Keystrokes.ps1', 'Get-GPPPassword.ps1', 'Usage.md', 'Invoke-Mimikatz.ps1',
           'Invoke-NinjaCopy.ps1', 'Invoke-TokenManipulation.ps1', 'Invoke-CredentialInjection.ps1',
           'VolumeShadowCopyTools.ps1', 'Get-VaultCredential.ps1', 'Get-VaultCredential.ps1xml',
           'Get-MicrophoneAudio.ps1', 'Get-GPPAutologon.ps1'

}
