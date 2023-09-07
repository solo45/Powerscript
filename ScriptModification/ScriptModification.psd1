@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'ScriptModification.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '1362d628-6c09-469e-99b3-6992cc56ac30'

# Author of this module
Author = 'Original Author Matthew Graeber'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'Powerscript Script Preparation/Modification Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = '*'

# List of all files packaged with this module
FileList = 'ScriptModification.psm1', 'ScriptModification.psd1', 'Out-CompressedDll.ps1', 'Out-EncodedCommand.ps1', 
               'Out-EncryptedScript.ps1', 'Remove-Comment.ps1', 'Usage.md'

}
