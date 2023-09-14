function favsig
{


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
        [UInt32]
        $StartByte,

        [Parameter(Mandatory = $True)]
        [String]
        $EndByte,

        [Parameter(Mandatory = $True)]
        [ValidateRange(0,4294967295)]
        [UInt32]
        $Interval,

        [String]
        [ValidateScript({Test-Path $_ })]
        $Path = ($pwd.path),

        [String]
        $OutPath = ($pwd),

        [ValidateRange(1,2097152)]
        [UInt32]
        $BufferLen = 65536,

        [Switch] $Force
    )

    
    if (!(Test-Path $Path)) {Throw "File path not found"}
    ${_/\__/==\__/\/==\} = $True
    if (!(Test-Path $OutPath)) {
        if ($Force -or (${_/\__/==\__/\/==\} = $psCmdlet.ShouldContinue($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIAAiACQATwB1AHQAUABhAHQAaAAiACAAZABvAGUAcwAgAG4AbwB0ACAAZQB4AGkAcwB0ACEAIABEAG8AIAB5AG8AdQAgAHcAYQBuAHQAIAB0AG8AIABjAHIAZQBhAHQAZQAgAHQAaABlACAAZABpAHIAZQBjAHQAbwByAHkAPwA='))),""))){new-item ($OutPath)-type directory}
    }
    if (!${_/\__/==\__/\/==\}) {Throw "Output path not found"}
    if (!(Get-ChildItem $Path).Exists) {Throw "File not found"}
    [Int32] ${/==\/=\_/\____/\/} = (Get-ChildItem $Path).Length
    if ($StartByte -gt (${/==\/=\_/\____/\/} - 1) -or $StartByte -lt 0) {Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AEIAeQB0AGUAIAByAGEAbgBnAGUAIABtAHUAcwB0ACAAYgBlACAAYgBlAHQAdwBlAGUAbgAgADAAIABhAG4AZAAgACQAewBfAF8AXwBfAF8ALwBcAC8AXABfAF8AXwAvAD0AXAAvAFwAfQA=')))}
    [Int32] ${_/\/====\_/=\___/} = ((${/==\/=\_/\____/\/}) - 1)
    if ($EndByte -ceq "max") {$EndByte = ${_/\/====\_/=\___/}}

    
    [Int32]$EndByte = $EndByte

    
    if ($EndByte -gt ${/==\/=\_/\____/\/}) {$EndByte = ${_/\/====\_/=\___/}}

    
    if ($EndByte -lt $StartByte) {$EndByte = $StartByte + $Interval}

    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AEIAeQB0AGUAOgAgACQAUwB0AGEAcgB0AEIAeQB0AGUA')))
    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGQAQgB5AHQAZQA6ACAAJABFAG4AZABCAHkAdABlAA==')))

    
    [String] ${_/\__/\_/\/==\/\/} = (Split-Path $Path -leaf).Split('.')[0]

    
    [Int32] ${_/\_/=\/====\__/=} = [Math]::Floor(($EndByte - $StartByte) / $Interval)
    if (((($EndByte - $StartByte) % $Interval)) -gt 0) {${_/\_/=\/====\__/=} = (${_/\_/=\/====\__/=} + 1)}

    
    ${_/\__/==\__/\/==\} = $True
    if ( $Force -or ( ${_/\__/==\__/\/==\} = $psCmdlet.ShouldContinue($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAHMAYwByAGkAcAB0ACAAdwBpAGwAbAAgAHIAZQBzAHUAbAB0ACAAaQBuACAAJAB7AF8AXwBfAC8AXABfAF8ALwBcAC8AXABfAF8ALwA9AFwALwB9ACAAYgBpAG4AYQByAGkAZQBzACAAYgBlAGkAbgBnACAAdwByAGkAdAB0AGUAbgAgAHQAbwAgACIAJABPAHUAdABQAGEAdABoACIAIQA='))),
             "Do you want to continue?"))){}
    if (!${_/\__/==\__/\/==\}) {Return}

    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAHMAYwByAGkAcAB0ACAAdwBpAGwAbAAgAG4AbwB3ACAAdwByAGkAdABlACAAJAB7AF8AXwBfAC8AXABfAF8ALwBcAC8AXABfAF8ALwA9AFwALwB9ACAAYgBpAG4AYQByAGkAZQBzACAAdABvACAAIgAkAE8AdQB0AFAAYQB0AGgAIgAuAA==')))
    [Int32] ${_/\/\/===\_______} = [Math]::Floor($Endbyte/$Interval)

    
    
    [Byte[]] ${__/\/\_/\_/\____/}=New-Object byte[] $BufferLen
    [System.IO.FileStream] ${___/==\____/=====} = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, $BufferLen)

    
    [Int32] ${/=====\/=\_/\__/\} = 0
    for (${/=====\/=\_/\__/\} -eq 0; ${/=====\/=\_/\__/\} -lt ${_/\_/=\/====\__/=} + 1 ; ${/=====\/=\_/\__/\}++)
    {
        
        if (${/=====\/=\_/\__/\} -eq ${_/\_/=\/====\__/=}) {[Int32]${/===\________/\__} = $EndByte}
        else {[Int32] ${/===\________/\__} = (($StartByte) + (($Interval) * (${/=====\/=\_/\__/\})))}

        Write-Verbose "Byte 0 -> $(${/===\________/\__})"

        
        ${___/==\____/=====}.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null

        
        [String] ${/===\/\_/\_/\/\__} = Join-Path $OutPath "$(${_/\__/\_/\/==\/\/})_$(${/===\________/\__}).bin"
        [System.IO.FileStream] ${___/\/\/===\/=\_/} = New-Object System.IO.FileStream(${/===\/\_/\_/\/\__}, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, $BufferLen)

        [Int32] ${/===\_/\/\___/==\} = ${/===\________/\__}
        Write-Verbose "$(${___/\/\/===\/=\_/}.name)"

        
        while (${/===\_/\/\___/==\} -gt $BufferLen){
            [Int32]${_/====\__/\/==\_/} = ${___/==\____/=====}.Read(${__/\/\_/\_/\____/}, 0, $BufferLen)
            ${___/\/\/===\/=\_/}.Write(${__/\/\_/\_/\____/}, 0, ${_/====\__/\/==\_/})
            ${/===\_/\/\___/==\} = ${/===\_/\/\___/==\} - ${_/====\__/\/==\_/}
        }

        
        do {
            [Int32]${_/====\__/\/==\_/} = ${___/==\____/=====}.Read(${__/\/\_/\_/\____/}, 0, ${/===\_/\/\___/==\})
            ${___/\/\/===\/=\_/}.Write(${__/\/\_/\_/\____/}, 0, ${_/====\__/\/==\_/})
            ${/===\_/\/\___/==\} = ${/===\_/\/\___/==\} - ${_/====\__/\/==\_/}
        }
        until (${/===\_/\/\___/==\} -eq 0)
        ${___/\/\/===\/=\_/}.Close()
        ${___/\/\/===\/=\_/}.Dispose()
    }
    Write-Verbose "Files written to disk. Flushing memory."
    ${___/==\____/=====}.Dispose()

    
    [System.GC]::Collect()
    Write-Verbose "Completed!"
}
