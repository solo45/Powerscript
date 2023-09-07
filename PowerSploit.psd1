@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Powerscript.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = 'f256376d-2058-449a-8bc3-61565e783cd4'

# Author of this module
Author = 'Original Author Matthew Graeber'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'Powerscript is a collection of Microsoft PowerShell modules that can be used to aid penetration testers and red team operator during all phases of an engagement.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(
    'Add-NetUser',
    'Add-ObjectAcl',
    'Add-Persistence',
    'Add-ServiceDacl',
    'Convert-NameToSid',
    'Convert-NT4toCanonical',
    'Convert-SidToName',
    'Copy-ClonedFile',
    'Find-AVSignature',
    'Find-ComputerField',
    'Find-ForeignGroup',
    'Find-ForeignUser',
    'Find-GPOComputerAdmin',
    'Find-GPOLocation',
    'Find-InterestingFile',
    'Find-LocalAdminAccess',
    'Find-PathDLLHijack',
    'Find-ProcessDLLHijack',
    'Find-ManagedSecurityGroups',
    'Find-UserField',
    'Get-ADObject',
    'Get-ApplicationHost',
    'Get-CachedRDPConnection',
    'Get-ComputerDetails',
    'Get-ComputerProperty',
    'Get-CurrentUserTokenGroupSid',
    'Get-DFSshare',
    'Get-DomainPolicy',
    'Get-ExploitableSystem',
    'Get-GPPPassword',
    'Get-HttpStatus',
    'Get-Keystrokes',
    'Get-LastLoggedOn',
    'Get-ModifiablePath',
    'Get-ModifiableRegistryAutoRun',
    'Get-ModifiableScheduledTaskFile',
    'Get-ModifiableService',
    'Get-ModifiableServiceFile',
    'Get-NetComputer',
    'Get-NetDomain',
    'Get-NetDomainController',
    'Get-NetDomainTrust',
    'Get-NetFileServer',
    'Get-NetForest',
    'Get-NetForestCatalog',
    'Get-NetForestDomain',
    'Get-NetForestTrust',
    'Get-NetGPO',
    'Get-NetGPOGroup',
    'Get-NetGroup',
    'Get-NetGroupMember',
    'Get-NetLocalGroup',
    'Get-NetLoggedon',
    'Get-NetOU',
    'Get-NetProcess',
    'Get-NetRDPSession',
    'Get-NetSession',
    'Get-NetShare',
    'Get-NetSite',
    'Get-NetSubnet',
    'Get-NetUser',
    'Get-ObjectAcl',
    'Get-PathAcl',
    'Get-Proxy',
    'Get-RegistryAlwaysInstallElevated',
    'Get-RegistryAutoLogon',
    'Get-SecurityPackages',
    'Get-ServiceDetail',
    'Get-SiteListPassword',
    'Get-System',
    'Get-TimedScreenshot',
    'Get-UnattendedInstallFile',
    'Get-UnquotedService',
    'Get-UserEvent',
    'Get-UserProperty',
    'Get-VaultCredential',
    'Get-VolumeShadowCopy',
    'Get-Webconfig',
    'Install-ServiceBinary',
    'Install-SSP',
    'Invoke-ACLScanner',
    'Invoke-CheckLocalAdminAccess',
    'Invoke-CredentialInjection',
    'Invoke-DllInjection',
    'Invoke-EnumerateLocalAdmin',
    'Invoke-EventHunter',
    'Invoke-FileFinder',
    'Invoke-MapDomainTrust',
    'Invoke-Mimikatz',
    'Invoke-NinjaCopy',
    'Invoke-Portscan',
    'Invoke-PrivescAudit',
    'Invoke-ProcessHunter',
    'Invoke-ReflectivePEInjection',
    'Invoke-ReverseDnsLookup',
    'Invoke-ServiceAbuse',
    'Invoke-ShareFinder',
    'Invoke-Shellcode',
    'Invoke-TokenManipulation',
    'Invoke-UserHunter',
    'Invoke-WmiCommand',
    'Mount-VolumeShadowCopy',
    'New-ElevatedPersistenceOption',
    'New-UserPersistenceOption',
    'New-VolumeShadowCopy',
    'Out-CompressedDll',
    'Out-EncodedCommand',
    'Out-EncryptedScript',
    'Out-Minidump',
    'Remove-Comments',
    'Remove-VolumeShadowCopy',
    'Restore-ServiceBinary',
    'Set-ADObject',
    'Set-CriticalProcess',
    'Set-MacAttribute',
    'Set-MasterBootRecord',
    'Set-ServiceBinPath',
    'Test-ServiceDaclPermission',
    'Write-HijackDll',
    'Write-ServiceBinary',
    'Write-UserAddMSI'
)

# List of all modules packaged with this module.
ModuleList = @( @{ModuleName = 'AntivirusBypass'; ModuleVersion = '1.0.0.0'; GUID = 'fb5ba434-5d90-4545-8363-859de1c8ef5a'},
                @{ModuleName = 'CodeExecution'; ModuleVersion = '1.0.0.0'; GUID = '4b5096a4-62a5-4a48-86fd-5e20494630ba'},
                @{ModuleName = 'Exfiltration'; ModuleVersion = '1.0.0.0'; GUID = '02373c76-f078-447e-8e9c-dfd32bcf6c5f'},
                @{ModuleName = 'Recon'; ModuleVersion = '1.0.0.0'; GUID = 'b29be398-0580-48a6-b437-426f7ff87b36'},
                @{ModuleName = 'ScriptModification'; ModuleVersion = '1.0.0.0'; GUID = '1362d628-6c09-469e-99b3-6992cc56ac30'},
                @{ModuleName = 'Persistence'; ModuleVersion = '1.0.0.0'; GUID = '1a3ad9a5-39cb-440d-97f6-2e40bee0754c'},
                @{ModuleName = 'PrivEsc'; ModuleVersion = '1.0.0.0'; GUID = '7da40a3d-731c-48be-88f5-1c8b437acfdd'} )

PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('security','pentesting','red team','offense')

        # A URL to the license for this module.
        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0.html'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/PowerShellMafia/Powerscript'

    }

}

}
