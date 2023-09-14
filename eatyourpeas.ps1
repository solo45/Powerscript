



[CmdletBinding()]
param(
  [switch]$TimeStamp
)


function __/===\_/=\/=\/\/\ {
  param(
    [string]$title
  )
  
  if (($title | sls -AllMatches -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBCACgAXABkAHsANAAsADYAfQApAA==')))).Matches.Value) {
    return (($title | sls -AllMatches -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBCACgAXABkAHsANAAsADYAfQApAA==')))).Matches.Value)
  }
  elseif (($title | sls -NotMatch -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBCACgAXABkAHsANAAsADYAfQApAA==')))).Matches.Value) {
    return (($title | sls -NotMatch -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBCACgAXABkAHsANAAsADYAfQApAA==')))).Matches.Value)
  }
}

Function ___/=\_/\___/\/\/= {
  param(
    $Target, $ServiceName)
  
  if ($null -ne $target) {
    try {
      ${/===\___/\/=\_/\_} = Get-Acl $target -ErrorAction SilentlyContinue
    }
    catch { $null }
    
    
    if (${/===\___/\/=\_/\_}) { 
      ${_/\/\_/====\_/\/\} = @()
      ${_/\/\_/====\_/\/\} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AEMATwBNAFAAVQBUAEUAUgBOAEEATQBFAFwAJABlAG4AdgA6AFUAUwBFAFIATgBBAE0ARQA=')))
      if (${/===\___/\/=\_/\_}.Owner -like ${_/\/\_/====\_/\/\} ) { Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABJAGQAZQBuAHQAaQB0AHkAIABoAGEAcwAgAG8AdwBuAGUAcgBzAGgAaQBwACAAbwBmACAAJABUAGEAcgBnAGUAdAA='))) -ForegroundColor Red }
      whoami.exe /groups /fo csv | ConvertFrom-Csv | select -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwACAAbgBhAG0AZQA='))) | % { ${_/\/\_/====\_/\/\} += $_ }
      ${_/\/\/\/==\__/\/=} = $false
      foreach (${_/=\_/==\/\/=\/==} in ${_/\/\_/====\_/\/\}) {
        ${/=\/\/===========} = ${/===\___/\/=\_/\_}.Access | ? { $_.IdentityReference -like ${_/=\_/==\/\/=\/==} }
        ${__/=\/\_/\__/==\/} = ""
        switch -WildCard (${/=\/\/===========}.FileSystemRights) {
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA=='))) { ${__/=\/\_/\__/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA=='))); ${_/\/\/\/==\__/\/=} = $true }
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlACoA'))) { ${__/=\/\_/\__/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))); ${_/\/\/\/==\__/\/=} = $true }
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA'))) { ${__/=\/\_/\__/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA'))); ${_/\/\/\/==\__/\/=} = $true }
        }
        Switch (${/=\/\/===========}.RegistryRights) {
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA=='))) { ${__/=\/\_/\__/==\/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA=='))); ${_/\/\/\/==\__/\/=} = $true }
        }
        if (${__/=\/\_/\__/==\/}) {
          if ($ServiceName) { Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABTAGUAcgB2AGkAYwBlAE4AYQBtAGUAIABmAG8AdQBuAGQAIAB3AGkAdABoACAAcABlAHIAbQBpAHMAcwBpAG8AbgBzACAAaQBzAHMAdQBlADoA'))) -ForegroundColor Red }
          Write-Host -ForegroundColor red  "Identity $(${/=\/\/===========}.IdentityReference) has '${__/=\/\_/\__/==\/}' perms for $Target"
        }
      }    
      
      if (${_/\/\/\/==\__/\/=} -eq $false) {
        if ($Target.Length -gt 3) {
          $Target = Split-Path $Target
          ___/=\_/\___/\/\/= $Target -ServiceName $ServiceName
        }
      }
    }
    else {
      
      $Target = Split-Path $Target
      ___/=\_/\___/\/\/= $Target $ServiceName
    }
  }
}

Function _/==\__/\_/\_/\_/\ {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBlAHQAYwBoAGkAbgBnACAAdABoAGUAIABsAGkAcwB0ACAAbwBmACAAcwBlAHIAdgBpAGMAZQBzACwAIAB0AGgAaQBzACAAbQBhAHkAIAB0AGEAawBlACAAYQAgAHcAaABpAGwAZQAuAC4ALgA=')));
  ${/==\/\/\_/\_____/} = gwmi -Class Win32_Service | ? { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OgBcAFwAVwBpAG4AZABvAHcAcwBcAFwA'))) -and ($_.StartMode -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA='))) -or $_.StartMode -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AdQBhAGwA')))) -and ($_.State -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AbgBpAG4AZwA='))) -or $_.State -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABwAGUAZAA=')))) };
  if ($(${/==\/\/\_/\_____/} | measure).Count -lt 1) {
    Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAdQBuAHEAdQBvAHQAZQBkACAAcwBlAHIAdgBpAGMAZQAgAHAAYQB0AGgAcwAgAHcAZQByAGUAIABmAG8AdQBuAGQA')));
  }
  else {
    ${/==\/\/\_/\_____/} | % {
      Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAHEAdQBvAHQAZQBkACAAUwBlAHIAdgBpAGMAZQAgAFAAYQB0AGgAIABmAG8AdQBuAGQAIQA='))) -ForegroundColor red
      Write-Host Name: $_.Name
      Write-Host PathName: $_.PathName
      Write-Host StartName: $_.StartName 
      Write-Host StartMode: $_.StartMode
      Write-Host Running: $_.State
    } 
  }
}

function __/==\_____/===\/\ { Write-Host "Time Running: $(${___/==\___/\____/}.Elapsed.Minutes):$(${___/==\___/\____/}.Elapsed.Seconds)" }

Function _/=\_/\_/\/\/====\ {
  Add-Type -AssemblyName PresentationCore
  ${_/\_/==\/\/\/==\_} = [Windows.Clipboard]::GetText()
  if (${_/\_/==\/\/\/==\_}) {
    Write-Host ""
    if ($TimeStamp) { __/==\_____/===\/\ }
    Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBsAGkAcABCAG8AYQByAGQAIAB0AGUAeAB0ACAAZgBvAHUAbgBkADoA')))
    Write-Host ${_/\_/==\/\/\/==\_}
    
  }
}
function h { Write-Host "##" -ForegroundColor Green }

$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgAgACAAIAAgACgAKAAsAC4ALAAvACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAvACwAIAAgACoALwAKACwALwAqACwALgAuACoAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgALAAKACwAKgAvACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoAC8ALAAgACAALgAqAC8ALwAoACgALwAvACoAKgAsACAALgAqACgAKAAoACgAKAAoACoACgAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACoAIAAqACoAKgAqACoALAAsACwALwAjACMAIwAjACMAIwAjACMAIwAjACAALgAoACoAIAAsACgAKAAoACgAKAAoAAoAKAAoACgAKAAoACgAKAAoACgAKAAoAC8AKgAgACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqAC8AIwAjACMAIwAjACMAIwAgAC4AKAAuACAAKAAoACgAKAAoACgACgAoACgAKAAoACgAKAAuAC4AKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoALwBAAEAAQABAAEAALwAqACoAKgAvACMAIwAjACMAIwAjACAALwAoACgAKAAoACgAKAAKACwALAAuAC4AKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgBAAEAAQABAAEAAQABAAEAAQABAACgAKgAqACoALAAjACMAIwAjACAALgAuAC8AKAAoACgAKAAoAAoALAAgACwAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAjAEAAQABAAEAAQAAjAEAAQABAAEAAKgAqACoAKgAqACoAKgAqACoAIwAjACgAKAAvACAALwAoACgAKAAoAAoALgAuACgAKAAoACMAIwAjACMAIwAjACMAIwAjACMAKgAqACoAKgAqACoAKgAqACoALwAjAEAAQABAAEAAQABAAEAAQABAAC8AKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAsACwALgAuACgAKAAoACgACgAuACgAKAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAKAAvACoAKgAqACoAKgAqAC8AQABAAEAAQABAACMAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAuAC4AIAAvACgAKAAKAC4AKAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACgALwAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAuAC4AKgAoAAoALgAoACgAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACgALwAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoALgAsACgACgAuACgAKAAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACgALwAqACoAKgAqACoAKgAqACoAKgAqACoAKgAqACoAKgAuAC4AKAAKAC4AKAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAoACoAKgAqACoAKgAqACoAKgAqACoAKgAqAC4ALgAoAAoALgAoACgAIwAjACMAIwAjACMAKAAsAC4AKgAqACoALgAsACgAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAoAC4ALgAqACoAKgAoAC8AKgAqACoAKgAqACoAKgAqACoALgAuACgACgAuACgAKAAjACMAIwAjACMAIwAqACgAIwAjACMAIwAjACgAKAAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAoACgAIwAjACMAIwAjACMALwAoACoAKgAqACoAKgAqACoAKgAuAC4AKAAKAC4AKAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACgALwAqACoAKgAqACoAKgAqACoAKgAqACgAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAoACoAKgAuAC4ALgAoAAoALgAoACgAKAAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMALwAqACoAKgAqACoAKgAqACgAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAuACgAKAAoACgACgAuACgAKAAoACgAKAAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMALwAgACAALwAoACgACgAuAC4AKAAoACgAKAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAoAC4ALgAoACgAKAAoACgALgAKAC4ALgAuAC4AKAAoACgAKAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAKAAgAC4AKAAoACgAKAAoACgALgAKAC4ALgAuAC4ALgAuACgAKAAoACgAKAAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAoACAALgAoACgAKAAoACgAKAAoAC4ACgAoACgAKAAoACgAKAAoACgAKAAuACAALAAoACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAKAAuAC4ALwAoACgAKAAoACgAKAAoACgAKAAuAAoAIAAgACgAKAAoACgAKAAoACgAKAAoAC8ALAAgACAALAAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAIwAjACMAKAAvAC4ALgAoACgAKAAoACgAKAAoACgAKAAoAC4ACgAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACgAKAAoACgALwAsAC4AIAAgACwAKgAvAC8ALwAvAC8ALwAqACwALgAgAC4ALwAoACgAKAAoACgAKAAoACgAKAAoACgALgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAoACgAKAAvAAoAIAAgACAAIAAgACAAIAAgACAAIABiAHkAIABDAGEAcgBsAG8AcwBQAG8AbABvAHAAIAAmACAAUgBhAG4AZABvAGwAcABoAEMAbwBuAGwAZQB5AAoA')))                  


${/==\/\__/====\/\/} = @{}
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHIAMQAgAE0ARAA1AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAGEAcAByADEAXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsAOAB9AFwAJABbAGEALQB6AEEALQBaADAALQA5AF8ALwBcAC4AXQB7ADIAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAGEAYwBoAGUAIABTAEgAQQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAB7AFMASABBAFwAfQBbADAALQA5AGEALQB6AEEALQBaAC8AXwA9AF0AewAxADAALAB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBsAG8AdwBmAGkAcwBoAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADIAWwBhAGIAeAB5AHoAXQA/AFwAJABbADAALQA5AF0AewAyAH0AXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdACoA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAHUAcABhAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAFMAXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsANQAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgBvAG8AbQBsAGEAdgBiAHUAbABsAGUAdABpAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAwAC0AOQBhAC0AegBBAC0AWgBdAHsAMwAyAH0AOgBbAGEALQB6AEEALQBaADAALQA5AF8AXQB7ADEANgAsADMAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABpAG4AdQB4ACAATQBEADUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEAXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsAOAB9AFwAJABbAGEALQB6AEEALQBaADAALQA5AF8ALwBcAC4AXQB7ADIAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABoAHAAYgBiADMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAEgAXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsAMwAxAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEANQAxADIAYwByAHkAcAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADYAXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsAMQA2AH0AXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsAOAA2AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABwAHIAZQBzAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAFAAXAAkAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAvAFwALgBdAHsAMwAxAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBkADUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABeAHwAWwBeAGEALQB6AEEALQBaADAALQA5AF0AKQBbAGEALQBmAEEALQBGADAALQA5AF0AewAzADIAfQAoAFsAXgBhAC0AegBBAC0AWgAwAC0AOQBdAHwAJAApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAMQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABeAHwAWwBeAGEALQB6AEEALQBaADAALQA5AF0AKQBbAGEALQBmAEEALQBGADAALQA5AF0AewA0ADAAfQAoAFsAXgBhAC0AegBBAC0AWgAwAC0AOQBdAHwAJAApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAMgA1ADYA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABeAHwAWwBeAGEALQB6AEEALQBaADAALQA5AF0AKQBbAGEALQBmAEEALQBGADAALQA5AF0AewA2ADQAfQAoAFsAXgBhAC0AegBBAC0AWgAwAC0AOQBdAHwAJAApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEANQAxADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABeAHwAWwBeAGEALQB6AEEALQBaADAALQA5AF0AKQBbAGEALQBmAEEALQBGADAALQA5AF0AewAxADIAOAB9ACgAWwBeAGEALQB6AEEALQBaADAALQA5AF0AfAAkACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAHQAaQBmAGEAYwB0AG8AcgB5ACAAQQBQAEkAIABUAG8AawBlAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBLAEMAWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsAMQAwACwAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAHQAaQBmAGEAYwB0AG8AcgB5ACAAUABhAHMAcwB3AG8AcgBkAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAFsAMAAtADkAQQBCAEMARABFAEYAXQBbAGEALQB6AEEALQBaADAALQA5AF0AewA4ACwAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgAgAEIAYQBzAGkAYwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAHMAaQBjACAAWwBhAC0AegBBAC0AWgAwAC0AOQBfADoAXAAuAD0AXAAtAF0AKwA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgAgAEIAZQBhAHIAZQByAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBlAGEAcgBlAHIAIABbAGEALQB6AEEALQBaADAALQA5AF8AXAAuAD0AXAAtAF0AKwA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGEAZgByAHUAaQB0ACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF8ALQBdAHsAMwAyAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG8AYgBlACAAQwBsAGkAZQBuAHQAIABJAGQAIAAoAE8AYQB1AHQAaAAgAFcAZQBiACkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbwBiAGUAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQBmADAALQA5AF0AewAzADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBiAG8AZABlACAAQwBsAGkAZQBuAHQAIABTAGUAYwByAGUAdAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwADgAZQAtACkAWwBhAC0AegAwAC0AOQBdAHsAMwAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBnAGUAIABTAGUAYwByAGUAdAAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBHAEUALQBTAEUAQwBSAEUAVAAtAEsARQBZAC0AMQBbAFEAUABaAFIAWQA5AFgAOABHAEYAMgBUAFYARABXADAAUwAzAEoATgA1ADQASwBIAEMARQA2AE0AVQBBADcATABdAHsANQA4AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBpAHIAdABhAGIAbABlACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAxADcAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGMAaABlAG0AaQAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGwAYwBoAGUAbQBpAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegBBAC0AWgAwAC0AOQAtAF0AewAzADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGkAYgBhAGIAYQAgAEEAYwBjAGUAcwBzACAASwBlAHkAIABJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABMAFQAQQBJACkAWwBhAC0AegAwAC0AOQBdAHsAMgAwAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGkAYgBhAGIAYQAgAFMAZQBjAHIAZQB0ACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGwAaQBiAGEAYgBhAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQBdAHsAMwAwAH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAHQAaQBmAGEAYwB0AG8AcgB5ACAAQQBQAEkAIABLAGUAeQAgACYAIABQAGEAcwBzAHcAbwByAGQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAiACcAXQBBAEsAQwBbAGEALQB6AEEALQBaADAALQA5AF0AewAxADAALAB9AFsAIgAnAF0AfABbACIAJwBdAEEAUABbADAALQA5AEEAQgBDAEQARQBGAF0AWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsAOAAsAH0AWwAiACcAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBzAGEAbgBhACAAQwBsAGkAZQBuAHQAIABJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGEAcwBhAG4AYQBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAMAAtADkAXQB7ADEANgB9ACkAWwAnACIAXQApAHwAKAAoAGEAcwBhAG4AYQBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADMAMgB9ACkAWwAnACIAXQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AGwAYQBzAHMAaQBhAG4AIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAHQAbABhAHMAcwBpAGEAbgBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADIANAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBXAFMAIABDAGwAaQBlAG4AdAAgAEkARAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABBADMAVABbAEEALQBaADAALQA5AF0AfABBAEsASQBBAHwAQQBHAFAAQQB8AEEASQBEAEEAfABBAFIATwBBAHwAQQBJAFAAQQB8AEEATgBQAEEAfABBAE4AVgBBAHwAQQBTAEkAQQApAFsAQQAtAFoAMAAtADkAXQB7ADEANgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBXAFMAIABNAFcAUwAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHoAbgBcAC4AbQB3AHMAXAAuAFsAMAAtADkAYQAtAGYAXQB7ADgAfQAtAFsAMAAtADkAYQAtAGYAXQB7ADQAfQAtAFsAMAAtADkAYQAtAGYAXQB7ADQAfQAtAFsAMAAtADkAYQAtAGYAXQB7ADQAfQAtAFsAMAAtADkAYQAtAGYAXQB7ADEAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBXAFMAIABTAGUAYwByAGUAdAAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQB3AHMAKAAuAHsAMAAsADIAMAB9ACkAPwBbACcAIgBdAFsAMAAtADkAYQAtAHoAQQAtAFoAXAAvACsAXQB7ADQAMAB9AFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBXAFMAIABBAHAAcABTAHkAbgBjACAARwByAGEAcABoAFEATAAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABhADIALQBbAGEALQB6ADAALQA5AF0AewAyADYAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQAzADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/ADoAWwBBAC0AWgAyAC0ANwBdAHsAOAB9ACkAKgAoAD8AOgBbAEEALQBaADIALQA3AF0AewAyAH0APQB7ADYAfQB8AFsAQQAtAFoAMgAtADcAXQB7ADQAfQA9AHsANAB9AHwAWwBBAC0AWgAyAC0ANwBdAHsANQB9AD0AewAzAH0AfABbAEEALQBaADIALQA3AF0AewA3AH0APQApAD8A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQA2ADQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABlAHkASgB8AFkAVABvAHwAVAB6AG8AfABQAEQAWwA4ADkAXQB8AGEASABSADAAYwBIAE0ANgBMAHwAYQBIAFIAMABjAEQAbwB8AHIATwAwACkAWwBhAC0AegBBAC0AWgAwAC0AOQArAC8AXQArAD0AewAwACwAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAAQQB1AHQAaAAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OgAvAC8AWwBhAC0AegBBAC0AWgAwAC0AOQBdACsAOgBbAGEALQB6AEEALQBaADAALQA5AF0AKwBAAFsAYQAtAHoAQQAtAFoAMAAtADkAXQArAFwALgBbAGEALQB6AEEALQBaAF0AKwA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBlAGEAbQBlAHIAIABDAGwAaQBlAG4AdAAgAFMAZQBjAHIAZQB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGUAYQBtAGUAcgBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAGIAXwBbAGEALQB6ADAALQA5AD0AXwBcAC0AXQB7ADQANAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQBuAGMAZQAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGkAbgBhAG4AYwBlAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsANgA0AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAHQAYgB1AGMAawBlAHQAIABDAGwAaQBlAG4AdAAgAEkAZAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGIAaQB0AGIAdQBjAGsAZQB0AFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQBdAHsAMwAyAH0AKQBbACcAIgBdACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAHQAYgB1AGMAawBlAHQAIABDAGwAaQBlAG4AdAAgAFMAZQBjAHIAZQB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGIAaQB0AGIAdQBjAGsAZQB0AFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQBfAFwALQBdAHsANgA0AH0AKQBbACcAIgBdACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAHQAYwBvAGkAbgBBAHYAZQByAGEAZwBlACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGkAdABjAG8AaQBuAC4APwBhAHYAZQByAGEAZwBlAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsANAAzAH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAHQAcQB1AGUAcgB5ACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGkAdABxAHUAZQByAHkAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAEEALQBaAGEALQB6ADAALQA5AF0AewAzADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAHQAdAByAGUAeAAgAEEAYwBjAGUAcwBzACAASwBlAHkAIABhAG4AZAAgAEEAYwBjAGUAcwBzACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAzADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAHIAaQBzAGUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGkAdAByAGkAcwBlAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegBBAC0AWgAwAC0AOQBfAFwALQBdAHsAOAA2AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBsAG8AYwBrACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGwAbwBjAGsAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQB6ADAALQA5AF0AewA0AH0ALQBbAGEALQB6ADAALQA5AF0AewA0AH0ALQBbAGEALQB6ADAALQA5AF0AewA0AH0ALQBbAGEALQB6ADAALQA5AF0AewA0AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBsAG8AYwBrAGMAaABhAGkAbgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBhAGkAbgBuAGUAdABbAGEALQB6AEEALQBaADAALQA5AF0AewAzADIAfQB8AHQAZQBzAHQAbgBlAHQAWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsAMwAyAH0AfABpAHAAZgBzAFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADMAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBsAG8AYwBrAGYAcgBvAHMAdAAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAGwAbwBjAGsAYwBoAGEAaQBuAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AZgAwAC0AOQBdAHsAOAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsANAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsANAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsANAB9AC0AWwAwAC0AOQBhAC0AZgBdAHsAMQAyAH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHgAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAG8AeABbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADMAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAGEAdgBlAG4AZQB3AGMAbwBpAG4AIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABiAHIAYQB2AGUAbgBlAHcAYwBvAGkAbgBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADUAMAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAGIAaQB0ACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBrAF8AWwBhAC0AegAwAC0AOQBdAHsAMwAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AagBhAHIAcwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABDAEwATwBKAEEAUgBTAF8AKQBbAGEALQB6AEEALQBaADAALQA5AF0AewA2ADAAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AdQBkAGkAbgBhAHIAeQAgAEIAYQBzAGkAYwAgAEEAdQB0AGgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBsAG8AdQBkAGkAbgBhAHIAeQA6AC8ALwBbADAALQA5AF0AewAxADUAfQA6AFsAMAAtADkAQQAtAFoAYQAtAHoAXQArAEAAWwBhAC0AegBdACsA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAGkAbgBiAGEAcwBlACAAQQBjAGMAZQBzAHMAIABUAG8AawBlAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF8ALQBdAHsANgA0AH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAGkAbgBsAGEAeQBlAHIAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABjAG8AaQBuAGwAYQB5AGUAcgBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADMAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAGkAbgBsAGkAYgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABjAG8AaQBuAGwAaQBiAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQBdAHsAMQA2AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AZgBsAHUAZQBuAHQAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgAgACYAIABTAGUAYwByAGUAdAAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAxADYAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdABmAHUAbAAgAGQAZQBsAGkAdgBlAHIAeQAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABjAG8AbgB0AGUAbgB0AGYAdQBsAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQA9AF8AXAAtAF0AewA0ADMAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHYAYQBsAGUAbgB0ACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBrAGUAeQBfAFsAYQAtAHoAMAAtADkAXQB7ADIANwB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBpAHQAeQAgAFMAZQBhAHIAYwBoACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABjAGgAYQByAGkAdAB5AC4APwBzAGUAYQByAGMAaABbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADMAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAHIAaQBjAGsAcwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABhAHAAaQBbAGEALQBoADAALQA5AF0AewAzADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABEAG8AdwBuAGwAbwBhAGQAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGQAbwB3AG4AbABvAGEAZABbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADIAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGYAaQBuAGUAZAAgAE4AZQB0AHcAbwByAGsAaQBuAGcAIABBAFAASQAgAHQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAG4AawBlAHkALQBbAGEALQB6ADAALQA5AD0AXwBcAC0AXQB7ADIANgB9AC0AWwBhAC0AegAwAC0AOQA9AF8AXAAtAF0AewA1ADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYwBvAHIAZAAgAEEAUABJACAASwBlAHkALAAgAEMAbABpAGUAbgB0ACAASQBEACAAJgAgAEMAbABpAGUAbgB0ACAAUwBlAGMAcgBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGQAaQBzAGMAbwByAGQAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQBoADAALQA5AF0AewA2ADQAfQB8AFsAMAAtADkAXQB7ADEAOAB9AHwAWwBhAC0AegAwAC0AOQA9AF8AXAAtAF0AewAzADIAfQApAFsAJwAiAF0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAG8AbgBlAGMAaQAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAzADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAG8AcABiAG8AeAAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBsAC4AWwBhAC0AegBBAC0AWgAwAC0AOQBfAC0AXQB7ADEAMwA2AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAHAAcABsAGUAcgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAHAAXAAuAHAAdABcAC4AKQBbAGEALQB6AEEALQBaADAALQA5AF0AewA0ADMAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAG8AcABiAG8AeAAgAEEAUABJACAAcwBlAGMAcgBlAHQALwBrAGUAeQAsACAAcwBoAG8AcgB0ACAAJgAgAGwAbwBuAGcAIABsAGkAdgBlAGQAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAHIAbwBwAGIAbwB4AFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQBdAHsAMQA1AH0AfABzAGwAXAAuAFsAYQAtAHoAMAAtADkAPQBfAFwALQBdAHsAMQAzADUAfQB8AFsAYQAtAHoAMAAtADkAXQB7ADEAMQB9ACgAQQBBAEEAQQBBAEEAQQBBAEEAQQApAFsAYQAtAHoAMAAtADkAXwA9AFwALQBdAHsANAAzAH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB1AGYAZgBlAGwAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZAB1AGYAZgBlAGwAXwAoAHQAZQBzAHQAfABsAGkAdgBlACkAXwBbAGEALQB6AEEALQBaADAALQA5AF8ALQBdAHsANAAzAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQB0AHIAYQBjAGUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZAB0ADAAYwAwADEAXAAuAFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADIANAB9AFwALgBbAGEALQB6ADAALQA5AF0AewA2ADQAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBhAHMAeQBQAG8AcwB0ACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBaAEEASwBbAGEALQB6AEEALQBaADAALQA5AF0AewA1ADQAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBhAHMAeQBQAG8AcwB0ACAAdABlAHMAdAAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBaAFQASwBbAGEALQB6AEEALQBaADAALQA5AF0AewA1ADQAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB0AGgAZQByAHMAYwBhAG4AIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABlAHQAaABlAHIAcwBjAGEAbgBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAQQAtAFoAMAAtADkAXQB7ADMANAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB0AHMAeQAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAyADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGMAZQBiAG8AbwBrACAAQQBjAGMAZQBzAHMAIABUAG8AawBlAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBBAEEAQwBFAGQARQBvAHMAZQAwAGMAQgBBAFsAMAAtADkAQQAtAFoAYQAtAHoAXQArAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGMAZQBiAG8AbwBrACAAQwBsAGkAZQBuAHQAIABJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGYARgBdAFsAYQBBAF0AWwBjAEMAXQBbAGUARQBdAFsAYgBCAF0AWwBvAE8AXQBbAG8ATwBdAFsAawBLAF0AfABbAGYARgBdAFsAYgBCAF0AKQAoAC4AewAwACwAMgAwAH0AKQA/AFsAJwAiAF0AWwAwAC0AOQBdAHsAMQAzACwAMQA3AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGMAZQBiAG8AbwBrACAATwBhAHUAdABoAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBmAEYAXQBbAGEAQQBdAFsAYwBDAF0AWwBlAEUAXQBbAGIAQgBdAFsAbwBPAF0AWwBvAE8AXQBbAGsASwBdAC4AKgBbACcAfAAiAF0AWwAwAC0AOQBhAC0AZgBdAHsAMwAyAH0AWwAnAHwAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGMAZQBiAG8AbwBrACAAUwBlAGMAcgBlAHQAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGYARgBdAFsAYQBBAF0AWwBjAEMAXQBbAGUARQBdAFsAYgBCAF0AWwBvAE8AXQBbAG8ATwBdAFsAawBLAF0AfABbAGYARgBdAFsAYgBCAF0AKQAoAC4AewAwACwAMgAwAH0AKQA/AFsAJwAiAF0AWwAwAC0AOQBhAC0AZgBdAHsAMwAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAHMAdABsAHkAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABmAGEAcwB0AGwAeQBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAPQBfAFwALQBdAHsAMwAyAH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AaQBjAGkAdAB5ACAAQQBQAEkAIABLAGUAeQAgACYAIABDAGwAaQBlAG4AdAAgAFMAZQBjAHIAZQB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABmAGkAbgBpAGMAaQB0AHkAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQBmADAALQA5AF0AewAzADIAfQB8AFsAYQAtAHoAMAAtADkAXQB7ADIAMAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGkAYwBrAHIAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAzADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHUAdAB0AGUAcgB3AGUAYQB2AGUAIABLAGUAeQBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBMAFcAUABVAEIASwBfAFQARQBTAFQALQBbAGEALQBoAEEALQBIADAALQA5AF0AewAzADIAfQAtAFgAfABGAEwAVwBTAEUAQwBLAF8AVABFAFMAVAAtAFsAYQAtAGgAQQAtAEgAMAAtADkAXQB7ADMAMgB9AC0AWAB8AEYATABXAFMARQBDAEsAXwBUAEUAUwBUAFsAYQAtAGgAQQAtAEgAMAAtADkAXQB7ADEAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAbQBlAC4AaQBvACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBpAG8ALQB1AC0AWwBhAC0AegBBAC0AWgAwAC0AOQBfAD0AXAAtAF0AewA2ADQAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAGIAbwBvAGsAcwAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewA2ADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAaAB1AGIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBpAHQAaAB1AGIAKAAuAHsAMAAsADIAMAB9ACkAPwBbACcAIgBdAFsAMAAtADkAYQAtAHoAQQAtAFoAXQB7ADMANQAsADQAMAB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAaAB1AGIAIABBAHAAcAAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAGgAdQB8AGcAaABzACkAXwBbADAALQA5AGEALQB6AEEALQBaAF0AewAzADYAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAaAB1AGIAIABPAEEAdQB0AGgAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBoAG8AXwBbADAALQA5AGEALQB6AEEALQBaAF0AewAzADYAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAaAB1AGIAIABQAGUAcgBzAG8AbgBhAGwAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBoAHAAXwBbADAALQA5AGEALQB6AEEALQBaAF0AewAzADYAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAaAB1AGIAIABSAGUAZgByAGUAcwBoACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBoAHIAXwBbADAALQA5AGEALQB6AEEALQBaAF0AewA3ADYAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQASAB1AGIAIABGAGkAbgBlAC0ARwByAGEAaQBuAGUAZAAgAFAAZQByAHMAbwBuAGEAbAAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBpAHQAaAB1AGIAXwBwAGEAdABfAFsAMAAtADkAYQAtAHoAQQAtAFoAXwBdAHsAOAAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAbABhAGIAIABQAGUAcgBzAG8AbgBhAGwAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBsAHAAYQB0AC0AWwAwAC0AOQBhAC0AegBBAC0AWgBcAC0AXQB7ADIAMAB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQATABhAGIAIABQAGkAcABlAGwAaQBuAGUAIABUAHIAaQBnAGcAZQByACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBsAHAAdAB0AC0AWwAwAC0AOQBhAC0AZgBdAHsANAAwAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQATABhAGIAIABSAHUAbgBuAGUAcgAgAFIAZQBnAGkAcwB0AHIAYQB0AGkAbwBuACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBSADEAMwA0ADgAOQA0ADEAWwAwAC0AOQBhAC0AegBBAC0AWgBfAFwALQBdAHsAMgAwAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBpAHQAdABlAHIAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF8ALQBdAHsANAAwAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAEMAYQByAGQAbABlAHMAcwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABpAHYAZQBfAFsAYQAtAHoAQQAtAFoAMAAtADkAXwA9AFwALQBdAHsANAAwAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAEYAaQBsAGUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAG8AZgBpAGwAZQBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADMAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAG8AZwBsAGUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBJAHoAYQBbADAALQA5AEEALQBaAGEALQB6AF8AXAAtAF0AewAzADUAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAG8AZwBsAGUAIABDAGwAbwB1AGQAIABQAGwAYQB0AGYAbwByAG0AIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAG8AbwBnAGwAZQB8AGcAYwBwAHwAeQBvAHUAdAB1AGIAZQB8AGQAcgBpAHYAZQB8AHkAdAApACgALgB7ADAALAAyADAAfQApAD8AWwAnACIAXQBbAEEASQB6AGEAWwAwAC0AOQBhAC0AegBfAFwALQBdAHsAMwA1AH0AXQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAG8AZwBsAGUAIABEAHIAaQB2AGUAIABPAGEAdQB0AGgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAwAC0AOQBdACsALQBbADAALQA5AEEALQBaAGEALQB6AF8AXQB7ADMAMgB9AFwALgBhAHAAcABzAFwALgBnAG8AbwBnAGwAZQB1AHMAZQByAGMAbwBuAHQAZQBuAHQAXAAuAGMAbwBtAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAG8AZwBsAGUAIABPAGEAdQB0AGgAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eQBhADIAOQBcAC4AWwAwAC0AOQBBAC0AWgBhAC0AegBfAFwALQBdACsA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAG8AZwBsAGUAIAAoAEcAQwBQACkAIABTAGUAcgB2AGkAYwBlAC0AYQBjAGMAbwB1AG4AdAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgB0AHkAcABlAC4AKwA6AC4AKwAiAHMAZQByAHYAaQBjAGUAXwBhAGMAYwBvAHUAbgB0AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAGEAZgBhAG4AYQAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQB5AEoAcgBJAGoAbwBpAFsAYQAtAHoAMAAtADkAXwA9AFwALQBdAHsANwAyACwAOQAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAGEAZgBhAG4AYQAgAGMAbABvAHUAZAAgAGEAcABpACAAdABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBsAGMAXwBbAEEALQBaAGEALQB6ADAALQA5AFwAKwAvAF0AewAzADIALAB9AD0AewAwACwAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAGEAZgBhAG4AYQAgAHMAZQByAHYAaQBjAGUAIABhAGMAYwBvAHUAbgB0ACAAdABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAGwAcwBhAF8AWwBBAC0AWgBhAC0AegAwAC0AOQBdAHsAMwAyAH0AXwBbAEEALQBGAGEALQBmADAALQA5AF0AewA4AH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABhAHMAaABpAGMAbwByAHAAIABUAGUAcgByAGEAZgBvAHIAbQAgAHUAcwBlAHIALwBvAHIAZwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBhAC0AegAwAC0AOQBdAHsAMQA0AH0AXAAuAGEAdABsAGEAcwB2ADEAXAAuAFsAYQAtAHoAMAAtADkAXwA9AFwALQBdAHsANgAwACwANwAwAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABlAHIAbwBrAHUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBoAEgAXQBbAGUARQBdAFsAcgBSAF0AWwBvAE8AXQBbAGsASwBdAFsAdQBVAF0ALgB7ADAALAAzADAAfQBbADAALQA5AEEALQBGAF0AewA4AH0ALQBbADAALQA5AEEALQBGAF0AewA0AH0ALQBbADAALQA5AEEALQBGAF0AewA0AH0ALQBbADAALQA5AEEALQBGAF0AewA0AH0ALQBbADAALQA5AEEALQBGAF0AewAxADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SAB1AGIAcwBwAG8AdAAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAnACIAXQBbAGEALQBoADAALQA5AF0AewA4AH0ALQBbAGEALQBoADAALQA5AF0AewA0AH0ALQBbAGEALQBoADAALQA5AF0AewA0AH0ALQBbAGEALQBoADAALQA5AF0AewA0AH0ALQBbAGEALQBoADAALQA5AF0AewAxADIAfQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHMAdABhAHQAdQBzACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABpAG4AcwB0AGEAdAB1AHMAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQB6ADAALQA5AF0AewAzADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGMAbwBtACAAQQBQAEkAIABLAGUAeQAgACYAIABDAGwAaQBlAG4AdAAgAFMAZQBjAHIAZQB0AC8ASQBEAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABpAG4AdABlAHIAYwBvAG0AWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQB6ADAALQA5AD0AXwBdAHsANgAwAH0AfABbAGEALQBoADAALQA5AF0AewA4AH0ALQBbAGEALQBoADAALQA5AF0AewA0AH0ALQBbAGEALQBoADAALQA5AF0AewA0AH0ALQBbAGEALQBoADAALQA5AF0AewA0AH0ALQBbAGEALQBoADAALQA5AF0AewAxADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBvAG4AaQBjACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABpAG8AbgBpAGMAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABpAG8AbgBfAFsAYQAtAHoAMAAtADkAXQB7ADQAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgBlAG4AawBpAG4AcwAgAEMAcgBlAGQAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PABbAGEALQB6AEEALQBaAF0AKgA+AHsAWwBhAC0AegBBAC0AWgAwAC0AOQA9ACsALwBdACoAfQA8AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgBTAE8ATgAgAFcAZQBiACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABlAHkAWwAwAC0AOQBhAC0AegBdAHsAMwAwACwAMwA0AH0AXAAuAGUAeQBbADAALQA5AGEALQB6AFwALwBfAFwALQBdAHsAMwAwACwAfQBcAC4AWwAwAC0AOQBhAC0AegBBAC0AWgBcAC8AXwBcAC0AXQB7ADEAMAAsAH0APQB7ADAALAAyAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwByAGEAawBlAG4AIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AFwALwA9AF8AXAArAFwALQBdAHsAOAAwACwAOQAwAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwB1AGMAbwBpAG4AIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQBmADAALQA5AF0AewAyADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwB1AGMAbwBpAG4AIABTAGUAYwByAGUAdAAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbADAALQA5AGEALQBmAF0AewA4AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewAxADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHUAbgBjAGgAZABhAHIAawBsAHkAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AD0AXwBcAC0AXQB7ADQAMAB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABpAG4AZQBhAHIAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABsAGkAbgBfAGEAcABpAF8AWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsANAAwAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABpAG4AZQBhAHIAIABDAGwAaQBlAG4AdAAgAFMAZQBjAHIAZQB0AC8ASQBEAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGwAaQBuAGUAYQByAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AZgAwAC0AOQBdAHsAMwAyAH0AKQBbACcAIgBdACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABpAG4AawBlAGQASQBuACAAQwBsAGkAZQBuAHQAIABJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABpAG4AawBlAGQAaQBuACgALgB7ADAALAAyADAAfQApAD8AWwAnACIAXQBbADAALQA5AGEALQB6AF0AewAxADIAfQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABpAG4AawBlAGQASQBuACAAUwBlAGMAcgBlAHQAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABpAG4AawBlAGQAaQBuACgALgB7ADAALAAyADAAfQApAD8AWwAnACIAXQBbADAALQA5AGEALQB6AF0AewAxADYAfQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGIAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGwAbwBiAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAKABsAGkAdgBlAHwAdABlAHMAdAApAF8AWwBhAC0AZgAwAC0AOQBdAHsAMwA1AH0AKQBbACcAIgBdACkAfAAoACgAbABvAGIAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKAAoAHQAZQBzAHQAfABsAGkAdgBlACkAXwBwAHUAYgBfAFsAYQAtAGYAMAAtADkAXQB7ADMAMQB9ACkAWwAnACIAXQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGIAIABQAHUAYgBsAGkAcwBoAGEAYgBsAGUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAHQAZQBzAHQAfABsAGkAdgBlACkAXwBwAHUAYgBfAFsAYQAtAGYAMAAtADkAXQB7ADMAMQB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGkAbABiAG8AeABWAGEAbABpAGQAYQB0AG8AcgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGEAaQBsAGIAbwB4AC4APwB2AGEAbABpAGQAYQB0AG8AcgBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAQQAtAFoAMAAtADkAXQB7ADIAMAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGkAbABjAGgAaQBtAHAAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAwAC0AOQBhAC0AZgBdAHsAMwAyAH0ALQB1AHMAWwAwAC0AOQBdAHsAMQAsADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGkAbABnAHUAbgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHkALQBbADAALQA5AGEALQB6AEEALQBaAF0AewAzADIAfQAnAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGkAbABnAHUAbgAgAFAAdQBiAGwAaQBjACAAVgBhAGwAaQBkAGEAdABpAG8AbgAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB1AGIAawBlAHkALQBbAGEALQBmADAALQA5AF0AewAzADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGkAbABnAHUAbgAgAFcAZQBiAGgAbwBvAGsAIABzAGkAZwBuAGkAbgBnACAAawBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBhAC0AaAAwAC0AOQBdAHsAMwAyAH0ALQBbAGEALQBoADAALQA5AF0AewA4AH0ALQBbAGEALQBoADAALQA5AF0AewA4AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHAAYgBvAHgAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwAGsAXAAuAFsAYQAtAHoAMAAtADkAXQB7ADYAMAB9AFwALgBbAGEALQB6ADAALQA5AF0AewAyADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHQAdABlAHIAbQBvAHMAdAAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAyADYAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBCAGkAcgBkACAAQQBQAEkAIABLAGUAeQAgACYAIABBAFAASQAgAGMAbABpAGUAbgB0ACAASQBEAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAcwBzAGEAZwBlAGIAaQByAGQAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQB6ADAALQA5AF0AewAyADUAfQB8AFsAYQAtAGgAMAAtADkAXQB7ADgAfQAtAFsAYQAtAGgAMAAtADkAXQB7ADQAfQAtAFsAYQAtAGgAMAAtADkAXQB7ADQAfQAtAFsAYQAtAGgAMAAtADkAXQB7ADQAfQAtAFsAYQAtAGgAMAAtADkAXQB7ADEAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABUAGUAYQBtAHMAIABXAGUAYgBoAG8AbwBrAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoAXAAvAFwALwBbAGEALQB6ADAALQA5AF0AKwBcAC4AdwBlAGIAaABvAG8AawBcAC4AbwBmAGYAaQBjAGUAXAAuAGMAbwBtAFwALwB3AGUAYgBoAG8AbwBrAGIAMgBcAC8AWwBhAC0AegAwAC0AOQBdAHsAOAB9AC0AKABbAGEALQB6ADAALQA5AF0AewA0AH0ALQApAHsAMwB9AFsAYQAtAHoAMAAtADkAXQB7ADEAMgB9AEAAWwBhAC0AegAwAC0AOQBdAHsAOAB9AC0AKABbAGEALQB6ADAALQA5AF0AewA0AH0ALQApAHsAMwB9AFsAYQAtAHoAMAAtADkAXQB7ADEAMgB9AFwALwBJAG4AYwBvAG0AaQBuAGcAVwBlAGIAaABvAG8AawBcAC8AWwBhAC0AegAwAC0AOQBdAHsAMwAyAH0AXAAvAFsAYQAtAHoAMAAtADkAXQB7ADgAfQAtACgAWwBhAC0AegAwAC0AOQBdAHsANAB9AC0AKQB7ADMAfQBbAGEALQB6ADAALQA5AF0AewAxADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGoAbwBBAHUAdABoACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBhAC0AZgAwAC0AOQBdAHsAOAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsANAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsANAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsANAB9AC0AWwBhAC0AZgAwAC0AOQBdAHsAMQAyAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAbABpAGYAeQAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AD0AXwBcAC0AXQB7ADQAMAAsADQANgB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABSAGUAbABpAGMAIABVAHMAZQByACAAQQBQAEkAIABLAGUAeQAsACAAVQBzAGUAcgAgAEEAUABJACAASQBEACAAJgAgAEkAbgBnAGUAcwB0ACAAQgByAG8AdwBzAGUAcgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABOAFIAQQBLAC0AWwBBAC0AWgAwAC0AOQBdAHsAMgA3AH0AKQB8ACgAKABuAGUAdwByAGUAbABpAGMAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAEEALQBaADAALQA5AF0AewA2ADQAfQApAFsAJwAiAF0AKQB8ACgATgBSAEoAUwAtAFsAYQAtAGYAMAAtADkAXQB7ADEAOQB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHcAbgBvAGQAZQBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAG8AdwBuAG8AZABlAHMAWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAEEALQBaAGEALQB6ADAALQA5AF0AewAzADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBwAG0AIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABuAHAAbQBfAFsAYQAtAHoAQQAtAFoAMAAtADkAXQB7ADMANgB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB5AHQAaQBtAGUAcwAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AD0AXwBcAC0AXQB7ADMAMgB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBrAHQAYQAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AD0AXwBcAC0AXQB7ADQAMgB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAEkAIABBAFAASQAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBrAC0AWwBBAC0AWgBhAC0AegAwAC0AOQBdAHsANAA4AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBSAEIAIABJAG4AdABlAGwAbABpAGcAZQBuAGMAZQAgAEEAYwBjAGUAcwBzACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAnACIAXQBbAGEALQBmADAALQA5AF0AewA4AH0ALQBbAGEALQBmADAALQA5AF0AewA0AH0ALQBbAGEALQBmADAALQA5AF0AewA0AH0ALQBbAGEALQBmADAALQA5AF0AewA0AH0ALQBbAGEALQBmADAALQA5AF0AewAxADIAfQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAdABlAGIAaQBuACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwAGEAcwB0AGUAYgBpAG4AWwBhAC0AegAwAC0AOQBfACAAXAAuACwAXAAtAF0AewAwACwAMgA1AH0AKQAoAD0AfAA+AHwAOgA9AHwAXAB8AFwAfAA6AHwAPAA9AHwAPQA+AHwAOgApAC4AewAwACwANQB9AFsAJwAiAF0AKABbAGEALQB6ADAALQA5AF0AewAzADIAfQApAFsAJwAiAF0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHkAUABhAGwAIABCAHIAYQBpAG4AdAByAGUAZQAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAZQBzAHMAXwB0AG8AawBlAG4AXAAkAHAAcgBvAGQAdQBjAHQAaQBvAG4AXAAkAFsAMAAtADkAYQAtAHoAXQB7ADEANgB9AFwAJABbADAALQA5AGEALQBmAF0AewAzADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABpAGMAYQB0AGkAYwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBrAF8AbABpAHYAZQBfAFsAMAAtADkAYQAtAHoAXQB7ADMAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABpAG4AYQB0AGEAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwAGkAbgBhAHQAYQBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADYANAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABsAGEAbgBlAHQAcwBjAGEAbABlACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABzAGMAYQBsAGUAXwB0AGsAbgBfAFsAYQAtAHoAQQAtAFoAMAAtADkAXwBcAC4AXAAtAF0AewA0ADMAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABsAGEAbgBlAHQAUwBjAGEAbABlACAATwBBAHUAdABoACAAdABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwAHMAYwBhAGwAZQBfAG8AYQB1AHQAaABfAFsAYQAtAHoAQQAtAFoAMAAtADkAXwBcAC4AXAAtAF0AewAzADIALAA2ADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABsAGEAbgBlAHQAcwBjAGEAbABlACAAUABhAHMAcwB3AG8AcgBkAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABzAGMAYQBsAGUAXwBwAHcAXwBbAGEALQB6AEEALQBaADAALQA5AF8AXAAuAFwALQBdAHsANAAzAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABsAGEAaQBkACAAQQBQAEkAIABUAG8AawBlAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGMAYwBlAHMAcwAtACgAPwA6AHMAYQBuAGQAYgBvAHgAfABkAGUAdgBlAGwAbwBwAG0AZQBuAHQAfABwAHIAbwBkAHUAYwB0AGkAbwBuACkALQBbADAALQA5AGEALQBmAF0AewA4AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewAxADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABsAGEAaQBkACAAQwBsAGkAZQBuAHQAIABJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAyADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABsAGEAaQBkACAAUwBlAGMAcgBlAHQAIABrAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAzADAAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAZgBlAGMAdAAgAEEAUABJACAAdABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwAG4AdQBfAFsAYQAtAHoAMAAtADkAXQB7ADMANgB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAdABtAGEAbgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABNAEEASwAtAFsAYQAtAGYAQQAtAEYAMAAtADkAXQB7ADIANAB9AC0AWwBhAC0AZgBBAC0ARgAwAC0AOQBdAHsAMwA0AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAEsAZQB5AHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAtAFwALQBcAC0AXAAtAFwALQBCAEUARwBJAE4AIABQAFIASQBWAEEAVABFACAASwBFAFkAXAAtAFwALQBcAC0AXAAtAFwALQB8AFwALQBcAC0AXAAtAFwALQBcAC0AQgBFAEcASQBOACAAUgBTAEEAIABQAFIASQBWAEEAVABFACAASwBFAFkAXAAtAFwALQBcAC0AXAAtAFwALQB8AFwALQBcAC0AXAAtAFwALQBcAC0AQgBFAEcASQBOACAATwBQAEUATgBTAFMASAAgAFAAUgBJAFYAQQBUAEUAIABLAEUAWQBcAC0AXAAtAFwALQBcAC0AXAAtAHwAXAAtAFwALQBcAC0AXAAtAFwALQBCAEUARwBJAE4AIABQAEcAUAAgAFAAUgBJAFYAQQBUAEUAIABLAEUAWQAgAEIATABPAEMASwBcAC0AXAAtAFwALQBcAC0AXAAtAHwAXAAtAFwALQBcAC0AXAAtAFwALQBCAEUARwBJAE4AIABEAFMAQQAgAFAAUgBJAFYAQQBUAEUAIABLAEUAWQBcAC0AXAAtAFwALQBcAC0AXAAtAHwAXAAtAFwALQBcAC0AXAAtAFwALQBCAEUARwBJAE4AIABFAEMAIABQAFIASQBWAEEAVABFACAASwBFAFkAXAAtAFwALQBcAC0AXAAtAFwALQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGwAdQBtAGkAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB1AGwALQBbAGEALQBmADAALQA5AF0AewA0ADAAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB5AFAASQAgAHUAcABsAG8AYQBkACAAdABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB5AHAAaQAtAEEAZwBFAEkAYwBIAGwAdwBhAFMANQB2AGMAbQBjAFsAQQAtAFoAYQAtAHoAMAAtADkAXwBcAC0AXQB7ADUAMAAsAH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGkAcAAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABxAHUAaQBwAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsAMQA1AH0APQBcAHwAWwAwAC0AOQBdAHsAMQAwAH0AXAB8AFsAYQAtAHoAQQAtAFoAMAAtADkAXAAvACsAXQB7ADQAMwB9AD0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHAAaQBkAEEAUABJACAAQQBjAGMAZQBzAHMAIABUAG8AawBlAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF8ALQBdAHsANQAwAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AGIAeQBnAGUAbQAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgB1AGIAeQBnAGUAbQBzAF8AWwBhAC0AZgAwAC0AOQBdAHsANAA4AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABtAGUAIABBAFAASQAgAHQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBkAG0AZQBfAFsAYQAtAHoAMAAtADkAXQB7ADcAMAB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABiAGkAcgBkACAAQQBjAGMAZQBzAHMAIABJAEQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbADAALQA5AGEALQBmAF0AewA4AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewA0AH0ALQBbADAALQA5AGEALQBmAF0AewAxADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABiAGkAcgBkACAAQQBjAGMAZQBzAHMAIABUAG8AawBlAG4A'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQBmADAALQA5AF0AewA0ADAAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABnAHIAaQBkACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBHAFwALgBbAGEALQB6AEEALQBaADAALQA5AF8AXAAuAFwALQBdAHsANgA2AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABpAG4AYgBsAHUAZQAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eABrAGUAeQBzAGkAYgAtAFsAYQAtAGYAMAAtADkAXQB7ADYANAB9AC0AWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsAMQA2AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AdAByAHkAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQBmADAALQA5AF0AewA2ADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGkAcABwAG8AIABBAFAASQAgAEsAZQB5ACwAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgAsACAAQwB1AHMAdABvAG0AIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgAsACAAUAByAGkAdgBhAHQAZQAgAEEAcABwACAAQQBjAGMAZQBzAHMAIABUAG8AawBlAG4AIAAmACAAUwBoAGEAcgBlAGQAIABTAGUAYwByAGUAdAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGkAcABwAG8AXwAoAGwAaQB2AGUAfAB0AGUAcwB0ACkAXwBbAGEALQBmADAALQA5AF0AewA0ADAAfQB8AHMAaABwAGEAdABfAFsAYQAtAGYAQQAtAEYAMAAtADkAXQB7ADMAMgB9AHwAcwBoAHAAYwBhAF8AWwBhAC0AZgBBAC0ARgAwAC0AOQBdAHsAMwAyAH0AfABzAGgAcABwAGEAXwBbAGEALQBmAEEALQBGADAALQA5AF0AewAzADIAfQB8AHMAaABwAHMAcwBfAFsAYQAtAGYAQQAtAEYAMAAtADkAXQB7ADMAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGQAZQBrAGkAcQAgAFMAZQBjAHIAZQB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQBmADAALQA5AF0AewA4AH0AOgBbAGEALQBmADAALQA5AF0AewA4AH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGQAZQBrAGkAcQAgAFMAZQBuAHMAaQB0AGkAdgBlACAAVQBSAEwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQBmADAALQA5AF0AewA4AH0AOgBbAGEALQBmADAALQA5AF0AewA4AH0AKQBAACgAPwA6AGcAZQBtAHMALgBjAG8AbgB0AHIAaQBiAHMAeQBzAC4AYwBvAG0AfABlAG4AdABlAHIAcAByAGkAcwBlAC4AYwBvAG4AdAByAGkAYgBzAHkAcwAuAGMAbwBtACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBsAGEAYwBrACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eABvAHgAWwBiAGEAcAByAHMAXQAtACgAWwAwAC0AOQBhAC0AegBBAC0AWgBdAHsAMQAwACwANAA4AH0AKQA/AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBsAGEAYwBrACAAVwBlAGIAaABvAG8AawA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGgAbwBvAGsAcwAuAHMAbABhAGMAawAuAGMAbwBtAC8AcwBlAHIAdgBpAGMAZQBzAC8AVABbAGEALQB6AEEALQBaADAALQA5AF8AXQB7ADEAMAB9AC8AQgBbAGEALQB6AEEALQBaADAALQA5AF8AXQB7ADEAMAB9AC8AWwBhAC0AegBBAC0AWgAwAC0AOQBfAF0AewAyADQAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBtAGEAcgBrAHMAaABlAGUAbAAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAG0AYQByAHQAcwBoAGUAZQB0AFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBhAC0AegAwAC0AOQBdAHsAMgA2AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBxAHUAYQByAGUAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBxAE8AYQB0AHAALQBbADAALQA5AEEALQBaAGEALQB6AF8AXAAtAF0AewAyADIAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBxAHUAYQByAGUAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBBAEEAQQBFAFsAYQAtAHoAQQAtAFoAMAAtADkAXwAtAF0AewA1ADkAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBxAHUAYQByAGUAIABPAGEAdQB0AGgAIABTAGUAYwByAGUAdAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBxADAAYwBzAHAALQBbACAAMAAtADkAQQAtAFoAYQAtAHoAXwBcAC0AXQB7ADQAMwB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHkAdABjAGgAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGMAcgBlAHQALQAuACoALQBbAGEALQB6AEEALQBaADAALQA5AF8APQBcAC0AXQB7ADMANgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBwAGUAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgAgACYAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGsAfABwAGsAKQBfACgAdABlAHMAdAB8AGwAaQB2AGUAKQBfAFsAMAAtADkAYQAtAHoAXQB7ADEAMAAsADMAMgB9AHwAawBfAGwAaQB2AGUAXwBbADAALQA5AGEALQB6AEEALQBaAF0AewAyADQAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AG0AbwBMAG8AZwBpAGMAIABBAGMAYwBlAHMAcwAgAEkARAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAxADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AG0AbwBMAG8AZwBpAGMAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewA2ADQAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABlAGwAZQBnAHIAYQBtACAAQgBvAHQAIABBAFAASQAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAwAC0AOQBdACsAOgBBAEEAWwAwAC0AOQBBAC0AWgBhAC0AegBcAFwALQBfAF0AewAzADMAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAdgBpAHMAIABDAEkAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewAyADIAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAbABsAG8AIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB0AHIAZQBsAGwAbwBbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAMAAtADkAYQAtAHoAXQB7ADMAMgB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB3AGkAbABpAG8AIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBLAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADMAMgB9AA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB3AGkAdABjAGgAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB0AHcAaQB0AGMAaABbAGEALQB6ADAALQA5AF8AIABcAC4ALABcAC0AXQB7ADAALAAyADUAfQApACgAPQB8AD4AfAA6AD0AfABcAHwAXAB8ADoAfAA8AD0AfAA9AD4AfAA6ACkALgB7ADAALAA1AH0AWwAnACIAXQAoAFsAYQAtAHoAMAAtADkAXQB7ADMAMAB9ACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB3AGkAdAB0AGUAcgAgAEMAbABpAGUAbgB0ACAASQBEAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwB0AFQAXQBbAHcAVwBdAFsAaQBJAF0AWwB0AFQAXQBbAHQAVABdAFsAZQBFAF0AWwByAFIAXQAoAC4AewAwACwAMgAwAH0AKQA/AFsAJwAiAF0AWwAwAC0AOQBhAC0AegBdAHsAMQA4ACwAMgA1AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB3AGkAdAB0AGUAcgAgAEIAZQBhAHIAZQByACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABBAHsAMgAyAH0AWwBhAC0AegBBAC0AWgAwAC0AOQAlAF0AewA4ADAALAAxADAAMAB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB3AGkAdAB0AGUAcgAgAE8AYQB1AHQAaAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwB0AFQAXQBbAHcAVwBdAFsAaQBJAF0AWwB0AFQAXQBbAHQAVABdAFsAZQBFAF0AWwByAFIAXQAuAHsAMAAsADMAMAB9AFsAJwAiAFwAXABzAF0AWwAwAC0AOQBhAC0AegBBAC0AWgBdAHsAMwA1ACwANAA0AH0AWwAnACIAXABcAHMAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB3AGkAdAB0AGUAcgAgAFMAZQBjAHIAZQB0ACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwB0AFQAXQBbAHcAVwBdAFsAaQBJAF0AWwB0AFQAXQBbAHQAVABdAFsAZQBFAF0AWwByAFIAXQAoAC4AewAwACwAMgAwAH0AKQA/AFsAJwAiAF0AWwAwAC0AOQBhAC0AegBdAHsAMwA1ACwANAA0AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQBmAG8AcgBtACAAQQBQAEkAIABLAGUAeQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABmAHAAXwBbAGEALQB6ADAALQA5AF8AXAAuAD0AXAAtAF0AewA1ADkAfQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBSAEwAUwBjAGEAbgAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAnACIAXQBbAGEALQBmADAALQA5AF0AewA4AH0ALQBbAGEALQBmADAALQA5AF0AewA0AH0ALQBbAGEALQBmADAALQA5AF0AewA0AH0ALQBbAGEALQBmADAALQA5AF0AewA0AH0ALQBbAGEALQBmADAALQA5AF0AewAxADIAfQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAHUAbAB0ACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBzAGIAXQBcAC4AWwBhAC0AegBBAC0AWgAwAC0AOQBdAHsAMgA0AH0A'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBhAG4AZABlAHgAIABBAGMAYwBlAHMAcwAgAFQAbwBrAGUAbgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB0ADEAXAAuAFsAQQAtAFoAMAAtADkAYQAtAHoAXwAtAF0AKwBbAD0AXQB7ADAALAAyAH0AXAAuAFsAQQAtAFoAMAAtADkAYQAtAHoAXwAtAF0AewA4ADYAfQBbAD0AXQB7ADAALAAyAH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBhAG4AZABlAHgAIABBAFAASQAgAEsAZQB5AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABBAFEAVgBOAFsAQQAtAFoAYQAtAHoAMAAtADkAXwBcAC0AXQB7ADMANQAsADMAOAB9ACkA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBhAG4AZABlAHgAIABBAFcAUwAgAEEAYwBjAGUAcwBzACAAVABvAGsAZQBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABZAEMAWwBhAC0AegBBAC0AWgAwAC0AOQBfAFwALQBdAHsAMwA4AH0AKQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBlAGIAMwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB3AGUAYgAzAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwBBAC0AWgBhAC0AegAwAC0AOQBfAD0AXAAtAF0AKwBcAC4AWwBBAC0AWgBhAC0AegAwAC0AOQBfAD0AXAAtAF0AKwBcAC4APwBbAEEALQBaAGEALQB6ADAALQA5AF8ALgArAC8APQBcAC0AXQAqACkAWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBlAG4AZABlAHMAawAgAFMAZQBjAHIAZQB0ACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABbAGEALQB6ADAALQA5AF0AewA0ADAAfQApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwAgAEEAUABJACAASwBlAHkA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAoAGsAZQB5AHwAYQBwAGkAfAB0AG8AawBlAG4AfABzAGUAYwByAGUAdAB8AHAAYQBzAHMAdwBvAHIAZAApAFsAYQAtAHoAMAAtADkAXwAgAFwALgAsAFwALQBdAHsAMAAsADIANQB9ACkAKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwAwAC0AOQBhAC0AegBBAC0AWgBfAD0AXAAtAF0AewA4ACwANgA0AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwAgAFMAZQBjAHIAZQB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBzAFMAXQBbAGUARQBdAFsAYwBDAF0AWwByAFIAXQBbAGUARQBdAFsAdABUAF0ALgAqAFsAJwAiAF0AWwAwAC0AOQBhAC0AegBBAC0AWgBdAHsAMwAyACwANAA1AH0AWwAnACIAXQA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAAQQB1AHQAaAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwAvACgALgArACkAOgAoAC4AKwApAEAA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABIAFAAIABQAGEAcwBzAHcAbwByAGQAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABwAHcAZAB8AHAAYQBzAHMAdwBkAHwAcABhAHMAcwB3AG8AcgBkAHwAUABBAFMAUwBXAEQAfABQAEEAUwBTAFcATwBSAEQAfABkAGIAdQBzAGUAcgB8AGQAYgBwAGEAcwBzAHwAcABhAHMAcwAnACkALgAqAFsAPQA6AF0ALgArAHwAZABlAGYAaQBuAGUAIAA/AFwAKAAnACgAXAB3ACoAcABhAHMAcwB8AFwAdwAqAHAAdwBkAHwAXAB3ACoAdQBzAGUAcgB8AFwAdwAqAGQAYQB0AGEAYgApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AZgBpAGcAIABTAGUAYwByAGUAdABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABhAHMAcwB3AGQALgAqAHwAYwByAGUAZABlAG4ALgAqAHwAXgBrAGkAbgBkADoAWwBeAGEALQB6AEEALQBaADAALQA5AF8AXQA/AFMAZQBjAHIAZQB0AHwAWwBeAGEALQB6AEEALQBaADAALQA5AF8AXQBlAG4AdgA6AHwAcwBlAGMAcgBlAHQAOgB8AHMAZQBjAHIAZQB0AE4AYQBtAGUAOgB8AF4AawBpAG4AZAA6AFsAXgBhAC0AegBBAC0AWgAwAC0AOQBfAF0APwBFAG4AYwByAHkAcAB0AGkAbwBuAEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4AfABcAC0AXAAtAGUAbgBjAHIAeQBwAHQAaQBvAG4AXAAtAHAAcgBvAHYAaQBkAGUAcgBcAC0AYwBvAG4AZgBpAGcA'))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAG0AcABsAGUAIABQAGEAcwBzAHcAbwByAGQAcwA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABhAHMAcwB3AC4AKgBbAD0AOgBdAC4AKwA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYQBjACAAQQBQAEkAIAB0AG8AawBlAG4AcwAgAHMAZQBhAHIAYwBoAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGMAYwBlAHMAcwBfAGsAZQB5AHwAYQBjAGMAZQBzAHMAXwB0AG8AawBlAG4AfABhAGQAbQBpAG4AXwBwAGEAcwBzAHwAYQBkAG0AaQBuAF8AdQBzAGUAcgB8AGEAbABnAG8AbABpAGEAXwBhAGQAbQBpAG4AXwBrAGUAeQB8AGEAbABnAG8AbABpAGEAXwBhAHAAaQBfAGsAZQB5AHwAYQBsAGkAYQBzAF8AcABhAHMAcwB8AGEAbABpAGMAbABvAHUAZABfAGEAYwBjAGUAcwBzAF8AawBlAHkAfAAgAGEAbQBhAHoAbwBuAF8AcwBlAGMAcgBlAHQAXwBhAGMAYwBlAHMAcwBfAGsAZQB5AHwAYQBtAGEAegBvAG4AYQB3AHMAfABhAG4AcwBpAGIAbABlAF8AdgBhAHUAbAB0AF8AcABhAHMAcwB3AG8AcgBkAHwAYQBvAHMAXwBrAGUAeQB8AGEAcABpAF8AawBlAHkAfABhAHAAaQBfAGsAZQB5AF8AcwBlAGMAcgBlAHQAfABhAHAAaQBfAGsAZQB5AF8AcwBpAGQAfABhAHAAaQBfAHMAZQBjAHIAZQB0AHwAIABhAHAAaQAuAGcAbwBvAGcAbABlAG0AYQBwAHMAIABBAEkAegBhAHwAYQBwAGkAZABvAGMAcwB8AGEAcABpAGsAZQB5AHwAYQBwAGkAUwBlAGMAcgBlAHQAfABhAHAAcABfAGQAZQBiAHUAZwB8AGEAcABwAF8AaQBkAHwAYQBwAHAAXwBrAGUAeQB8AGEAcABwAF8AbABvAGcAXwBsAGUAdgBlAGwAfABhAHAAcABfAHMAZQBjAHIAZQB0AHwAYQBwAHAAawBlAHkAfABhAHAAcABrAGUAeQBzAGUAYwByAGUAdAB8ACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAF8AawBlAHkAfABhAHAAcABzAGUAYwByAGUAdAB8AGEAcABwAHMAcABvAHQAfABhAHUAdABoAF8AdABvAGsAZQBuAHwAYQB1AHQAaABvAHIAaQB6AGEAdABpAG8AbgBUAG8AawBlAG4AfABhAHUAdABoAHMAZQBjAHIAZQB0AHwAYQB3AHMAXwBhAGMAYwBlAHMAcwB8AGEAdwBzAF8AYQBjAGMAZQBzAHMAXwBrAGUAeQBfAGkAZAB8AGEAdwBzAF8AYgB1AGMAawBlAHQAfAAgAGEAdwBzAF8AawBlAHkAfABhAHcAcwBfAHMAZQBjAHIAZQB0AHwAYQB3AHMAXwBzAGUAYwByAGUAdABfAGsAZQB5AHwAYQB3AHMAXwB0AG8AawBlAG4AfABBAFcAUwBTAGUAYwByAGUAdABLAGUAeQB8AGIAMgBfAGEAcABwAF8AawBlAHkAfABiAGEAcwBoAHIAYwAgAHAAYQBzAHMAdwBvAHIAZAB8ACAAYgBpAG4AdAByAGEAeQBfAGEAcABpAGsAZQB5AHwAYgBpAG4AdAByAGEAeQBfAGcAcABnAF8AcABhAHMAcwB3AG8AcgBkAHwAYgBpAG4AdAByAGEAeQBfAGsAZQB5AHwAYgBpAG4AdAByAGEAeQBrAGUAeQB8AGIAbAB1AGUAbQBpAHgAXwBhAHAAaQBfAGsAZQB5AHwAYgBsAHUAZQBtAGkAeABfAHAAYQBzAHMAfABiAHIAbwB3AHMAZQByAHMAdABhAGMAawBfAGEAYwBjAGUAcwBzAF8AawBlAHkAfAAgAGIAdQBjAGsAZQB0AF8AcABhAHMAcwB3AG8AcgBkAHwAYgB1AGMAawBlAHQAZQBlAHIAXwBhAHcAcwBfAGEAYwBjAGUAcwBzAF8AawBlAHkAXwBpAGQAfABiAHUAYwBrAGUAdABlAGUAcgBfAGEAdwBzAF8AcwBlAGMAcgBlAHQAXwBhAGMAYwBlAHMAcwBfAGsAZQB5AHwAYgB1AGkAbAB0AF8AYgByAGEAbgBjAGgAXwBkAGUAcABsAG8AeQBfAGsAZQB5AHwAYgB4AF8AcABhAHMAcwB3AG8AcgBkAHwAYwBhAGMAaABlAF8AZAByAGkAdgBlAHIAfAAgAGMAYQBjAGgAZQBfAHMAMwBfAHMAZQBjAHIAZQB0AF8AawBlAHkAfABjAGEAdAB0AGwAZQBfAGEAYwBjAGUAcwBzAF8AawBlAHkAfABjAGEAdAB0AGwAZQBfAHMAZQBjAHIAZQB0AF8AawBlAHkAfABjAGUAcgB0AGkAZgBpAGMAYQB0AGUAXwBwAGEAcwBzAHcAbwByAGQAfABjAGkAXwBkAGUAcABsAG8AeQBfAHAAYQBzAHMAdwBvAHIAZAB8AGMAbABpAGUAbgB0AF8AcwBlAGMAcgBlAHQAfAAgAGMAbABpAGUAbgB0AF8AegBwAGsAXwBzAGUAYwByAGUAdABfAGsAZQB5AHwAYwBsAG8AagBhAHIAcwBfAHAAYQBzAHMAdwBvAHIAZAB8AGMAbABvAHUAZABfAGEAcABpAF8AawBlAHkAfABjAGwAbwB1AGQAXwB3AGEAdABjAGgAXwBhAHcAcwBfAGEAYwBjAGUAcwBzAF8AawBlAHkAfABjAGwAbwB1AGQAYQBuAHQAXwBwAGEAcwBzAHcAbwByAGQAfAAgAGMAbABvAHUAZABmAGwAYQByAGUAXwBhAHAAaQBfAGsAZQB5AHwAYwBsAG8AdQBkAGYAbABhAHIAZQBfAGEAdQB0AGgAXwBrAGUAeQB8AGMAbABvAHUAZABpAG4AYQByAHkAXwBhAHAAaQBfAHMAZQBjAHIAZQB0AHwAYwBsAG8AdQBkAGkAbgBhAHIAeQBfAG4AYQBtAGUAfABjAG8AZABlAGMAbwB2AF8AdABvAGsAZQBuAHwAYwBvAG4AbgAuAGwAbwBnAGkAbgB8ACAAYwBvAG4AbgBlAGMAdABpAG8AbgBzAHQAcgBpAG4AZwB8AGMAbwBuAHMAdQBtAGUAcgBfAGsAZQB5AHwAYwBvAG4AcwB1AG0AZQByAF8AcwBlAGMAcgBlAHQAfABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAfABjAHkAcAByAGUAcwBzAF8AcgBlAGMAbwByAGQAXwBrAGUAeQB8AGQAYQB0AGEAYgBhAHMAZQBfAHAAYQBzAHMAdwBvAHIAZAB8AGQAYQB0AGEAYgBhAHMAZQBfAHMAYwBoAGUAbQBhAF8AdABlAHMAdAB8ACAAZABhAHQAYQBkAG8AZwBfAGEAcABpAF8AawBlAHkAfABkAGEAdABhAGQAbwBnAF8AYQBwAHAAXwBrAGUAeQB8AGQAYgBfAHAAYQBzAHMAdwBvAHIAZAB8AGQAYgBfAHMAZQByAHYAZQByAHwAZABiAF8AdQBzAGUAcgBuAGEAbQBlAHwAZABiAHAAYQBzAHMAdwBkAHwAZABiAHAAYQBzAHMAdwBvAHIAZAB8AGQAYgB1AHMAZQByAHwAZABlAHAAbABvAHkAXwBwAGEAcwBzAHcAbwByAGQAfAAgAGQAaQBnAGkAdABhAGwAbwBjAGUAYQBuAF8AcwBzAGgAXwBrAGUAeQBfAGIAbwBkAHkAfABkAGkAZwBpAHQAYQBsAG8AYwBlAGEAbgBfAHMAcwBoAF8AawBlAHkAXwBpAGQAcwB8AGQAbwBjAGsAZQByAF8AaAB1AGIAXwBwAGEAcwBzAHcAbwByAGQAfABkAG8AYwBrAGUAcgBfAGsAZQB5AHwAZABvAGMAawBlAHIAXwBwAGEAcwBzAHwAZABvAGMAawBlAHIAXwBwAGEAcwBzAHcAZAB8ACAAZABvAGMAawBlAHIAXwBwAGEAcwBzAHcAbwByAGQAfABkAG8AYwBrAGUAcgBoAHUAYgBfAHAAYQBzAHMAdwBvAHIAZAB8AGQAbwBjAGsAZQByAGgAdQBiAHAAYQBzAHMAdwBvAHIAZAB8AGQAbwB0AC0AZgBpAGwAZQBzAHwAZABvAHQAZgBpAGwAZQBzAHwAZAByAG8AcABsAGUAdABfAHQAcgBhAHYAaQBzAF8AcABhAHMAcwB3AG8AcgBkAHwAZAB5AG4AYQBtAG8AYQBjAGMAZQBzAHMAawBlAHkAaQBkAHwAIABkAHkAbgBhAG0AbwBzAGUAYwByAGUAdABhAGMAYwBlAHMAcwBrAGUAeQB8AGUAbABhAHMAdABpAGMAYQBfAGgAbwBzAHQAfABlAGwAYQBzAHQAaQBjAGEAXwBwAG8AcgB0AHwAZQBsAGEAcwB0AGkAYwBzAGUAYQByAGMAaABfAHAAYQBzAHMAdwBvAHIAZAB8AGUAbgBjAHIAeQBwAHQAaQBvAG4AXwBrAGUAeQB8AGUAbgBjAHIAeQBwAHQAaQBvAG4AXwBwAGEAcwBzAHcAbwByAGQAfAAgAGUAbgB2AC4AaABlAHIAbwBrAHUAXwBhAHAAaQBfAGsAZQB5AHwAZQBuAHYALgBzAG8AbgBhAHQAeQBwAGUAXwBwAGEAcwBzAHcAbwByAGQAfABlAHUAcgBlAGsAYQAuAGEAdwBzAHMAZQBjAHIAZQB0AGsAZQB5ACkAWwBhAC0AegAwAC0AOQBfACAALgAsADwAXAAtAF0AewAwACwAMgA1AH0AKAA9AHwAPgB8ADoAPQB8AFwAfABcAHwAOgB8ADwAPQB8AD0APgB8ADoAKQAuAHsAMAAsADUAfQBbACcAIgBdACgAWwAwAC0AOQBhAC0AegBBAC0AWgBfAD0AXAAtAF0AewA4ACwANgA0AH0AKQBbACcAIgBdAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBuAGEAbQBlAC4AKgBbAD0AOgBdAC4AKwA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAIAB1AHMAZQByACAAYQBkAGQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAIAB1AHMAZQByACAALgArACAALwBhAGQAZAA='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAyADUAWwAwAC0ANQBdAHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAWwAwADEAXQA/AFsAMAAtADkAXQBbADAALQA5AF0APwApAFwALgAoADIANQBbADAALQA1AF0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfABbADAAMQBdAD8AWwAwAC0AOQBdAFsAMAAtADkAXQA/ACkAXAAuACgAMgA1AFsAMAAtADUAXQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8AFsAMAAxAF0APwBbADAALQA5AF0AWwAwAC0AOQBdAD8AKQBcAC4AKAAyADUAWwAwAC0ANQBdAHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAWwAwADEAXQA/AFsAMAAtADkAXQBbADAALQA5AF0APwApAA=='))))
${/==\/\__/====\/\/}.add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBtAGEAaQBsAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBBAC0AWgBhAC0AegAwAC0AOQAuAF8AJQArAC0AXQArAEAAWwBBAC0AWgBhAC0AegAwAC0AOQAuAC0AXQArAFwALgBbAEEALQBaAGEALQB6AF0AewAyACwANgB9AA=='))))


${___/==\___/\____/} = [system.diagnostics.stopwatch]::StartNew()

Write-Host -ForegroundColor cyan  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAFYASQBTAE8AUgBZADoAIABXAGkAbgBQAEUAQQBTACAALQAgAFcAaQBuAGQAbwB3AHMAIABsAG8AYwBhAGwAIABQAHIAaQB2AGkAbABlAGcAZQAgAEUAcwBjAGEAbABhAHQAaQBvAG4AIABBAHcAZQBzAG8AbQBlACAAUwBjAHIAaQBwAHQA')))
Write-Host -ForegroundColor cyan  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUABFAEEAUwAgAHMAaABvAHUAbABkACAAYgBlACAAdQBzAGUAZAAgAGYAbwByACAAYQB1AHQAaABvAHIAaQB6AGUAZAAgAHAAZQBuAGUAdAByAGEAdABpAG8AbgAgAHQAZQBzAHQAaQBuAGcAIABhAG4AZAAvAG8AcgAgAGUAZAB1AGMAYQB0AGkAbwBuAGEAbAAgAHAAdQByAHAAbwBzAGUAcwAgAG8AbgBsAHkA')))
Write-Host -ForegroundColor cyan  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHkAIABtAGkAcwB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABzAG8AZgB0AHcAYQByAGUAIAB3AGkAbABsACAAbgBvAHQAIABiAGUAIAB0AGgAZQAgAHIAZQBzAHAAbwBuAHMAaQBiAGkAbABpAHQAeQAgAG8AZgAgAHQAaABlACAAYQB1AHQAaABvAHIAIABvAHIAIABvAGYAIABhAG4AeQAgAG8AdABoAGUAcgAgAGMAbwBsAGwAYQBiAG8AcgBhAHQAbwByAA==')))
Write-Host -ForegroundColor cyan  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABpAHQAIABhAHQAIAB5AG8AdQByACAAbwB3AG4AIABuAGUAdAB3AG8AcgBrAHMAIABhAG4AZAAvAG8AcgAgAHcAaQB0AGgAIAB0AGgAZQAgAG4AZQB0AHcAbwByAGsAIABvAHcAbgBlAHIAJwBzACAAZQB4AHAAbABpAGMAaQB0ACAAcABlAHIAbQBpAHMAcwBpAG8AbgA=')))



Write-Host -ForegroundColor red  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAaQBjAGEAdABlAHMAIABzAHAAZQBjAGkAYQBsACAAcAByAGkAdgBpAGwAZQBnAGUAIABvAHYAZQByACAAYQBuACAAbwBiAGoAZQBjAHQAIABvAHIAIABtAGkAcwBjAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuAA==')))
Write-Host -ForegroundColor green  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAaQBjAGEAdABlAHMAIABwAHIAbwB0AGUAYwB0AGkAbwBuACAAaQBzACAAZQBuAGEAYgBsAGUAZAAgAG8AcgAgAHMAbwBtAGUAdABoAGkAbgBnACAAaQBzACAAdwBlAGwAbAAgAGMAbwBuAGYAaQBnAHUAcgBlAGQA')))
Write-Host -ForegroundColor cyan  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAaQBjAGEAdABlAHMAIABhAGMAdABpAHYAZQAgAHUAcwBlAHIAcwA=')))
Write-Host -ForegroundColor Gray  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAaQBjAGEAdABlAHMAIABkAGkAcwBhAGIAbABlAGQAIAB1AHMAZQByAHMA')))
Write-Host -ForegroundColor yellow  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAaQBjAGEAdABlAHMAIABsAGkAbgBrAHMA')))
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAaQBjAGEAdABlAHMAIAB0AGkAdABsAGUA')))


Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABjAGEAbgAgAGYAaQBuAGQAIABhACAAVwBpAG4AZABvAHcAcwAgAGwAbwBjAGEAbAAgAFAARQAgAEMAaABlAGMAawBsAGkAcwB0ACAAaABlAHIAZQA6ACAAaAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwBjAGgAZQBjAGsAbABpAHMAdAAtAHcAaQBuAGQAbwB3AHMALQBwAHIAaQB2AGkAbABlAGcAZQAtAGUAcwBjAGEAbABhAHQAaQBvAG4A'))) -ForegroundColor Yellow







Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0AfAB8AFMAWQBTAFQARQBNACAASQBOAEYATwBSAE0AQQBUAEkATwBOACAAfAB8AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AD0APQA9AA==')))
$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGkAcwAgAGMAdQByAGEAdABlAGQALgAgAFQAbwAgAGcAZQB0ACAAYQAgAGYAdQBsAGwAIABsAGkAcwB0ACAAbwBmACAAcwB5AHMAdABlAG0AIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ALAAgAHIAdQBuACAAdABoAGUAIABjAG0AZABsAGUAdAAgAGcAZQB0AC0AYwBvAG0AcAB1AHQAZQByAGkAbgBmAG8A')))


systeminfo.exe



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVwBJAE4ARABPAFcAUwAgAEgATwBUAEYASQBYAEUAUwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQB8ACAAQwBoAGUAYwBrACAAaQBmACAAdwBpAG4AZABvAHcAcwAgAGkAcwAgAHYAdQBsAG4AZQByAGEAYgBsAGUAIAB3AGkAdABoACAAVwBhAHQAcwBvAG4AIABoAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAHIAYQBzAHQAYQAtAG0AbwB1AHMAZQAvAFcAYQB0AHMAbwBuAA=='))) -ForegroundColor Yellow
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAcwBpAGIAbABlACAAZQB4AHAAbABvAGkAdABzACAAKABoAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAGMAbwBkAGkAbgBnAG8ALwBPAFMAQwBQAC0AMgAvAGIAbABvAGIALwBtAGEAcwB0AGUAcgAvAFcAaQBuAGQAbwB3AHMALwBXAGkAbgBQAHIAaQB2AEMAaABlAGMAawAuAGIAYQB0ACkA'))) -ForegroundColor Yellow
${/==\/==\__/\/=\_/} = Get-HotFix | sort -Descending -Property InstalledOn -ErrorAction SilentlyContinue | select HotfixID, Description, InstalledBy, InstalledOn
${/==\/==\__/\/=\_/} | ft -AutoSize



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQBMAEwAIABVAFAARABBAFQARQBTACAASQBOAFMAVABBAEwATABFAEQA')))






${/=\/==\/\_/=\____} = (New-Object -ComObject $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBVAHAAZABhAHQAZQAuAFMAZQBzAHMAaQBvAG4A'))))

${_/\/==\__/\_____/} = ${/=\/==\/\_/=\____}.QueryHistory("", 0, 1000) | select ResultCode, Date, Title


${_/\_/\/=\__/=\_/=} = @()


${__/\/\_/\_/===\/=} = @()


for (${_/=\_/==\/\/=\/==} = 0; ${_/=\_/==\/\/=\/==} -lt ${_/\/==\__/\_____/}.Count; ${_/=\_/==\/\/=\/==}++) {
  ${_/\/\_/==\/\/=\_/} = __/===\_/=\/=\/\/\ -title ${_/\/==\__/\_____/}[${_/=\_/==\/\/=\/==}].Title
  if (${_/\_/\/=\__/=\_/=} -like ${_/\/\_/==\/\/=\_/}) {
    
  }
  else {
    ${_/\_/\/=\__/=\_/=} += ${_/\/\_/==\/\/=\_/}
    ${__/\/\_/\_/===\/=} += ${_/=\_/==\/\/=\/==}
  }
}
${/==\_/===\_/\____} = @()

${__/\/\_/\_/===\/=} | % {
  ${____/\_/\/\__/\/\} = ${_/\/==\__/\_____/}[$_]
  ${/====\/==\_/===\_} = ${____/\_/\/\__/\/\}.ResultCode
  
  switch (${/====\/==\_/===\_}) {
    1 {
      ${/====\/==\_/===\_} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAHMAcwBpAG4AZwAvAFMAdQBwAGUAcgBzAGUAZABlAGQA')))
    }
    2 {
      ${/====\/==\_/===\_} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGMAYwBlAGUAZABlAGQA')))
    }
    3 {
      ${/====\/==\_/===\_} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGMAYwBlAGUAZABlAGQAIABXAGkAdABoACAARQByAHIAbwByAHMA')))
    }
    4 {
      ${/====\/==\_/===\_} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGkAbABlAGQA')))
    }
    5 {
      ${/====\/==\_/===\_} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AYwBlAGwAZQBkAA==')))
    }
  }
  ${/==\_/===\_/\____} += [PSCustomObject]@{
    Result = ${/====\/==\_/===\_}
    Date   = ${____/\_/\/\__/\/\}.Date
    Title  = ${____/\_/\/\__/\/\}.Title
  }    
}
${/==\_/===\_/\____} | ft -AutoSize


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAARAByAGkAdgBlACAASQBuAGYAbwA=')))

Add-Type -AssemblyName System.Management


${__/=\/==\/====\/\} = New-Object System.Management.ManagementObjectSearcher($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAEwARQBDAFQAIAAqACAARgBSAE8ATQAgAFcAaQBuADMAMgBfAEwAbwBnAGkAYwBhAGwARABpAHMAawAgAFcASABFAFIARQAgAEQAcgBpAHYAZQBUAHkAcABlACAAPQAgADMA'))))


${/=\/\_/\/=\_/\/\/} = ${__/=\/==\/====\/\}.Get()


foreach (${__/\/\/===\/=\/\_} in ${/=\/\_/\/=\_/\/\/}) {
  ${_/\_/=\_/\/\_/==\} = ${__/\/\/===\/=\/\_}.DeviceID
  ${___/\/\/\__/\/\/\} = ${__/\/\/===\/=\/\_}.VolumeName
  ${__/\/\_/=====\/=\} = [math]::Round(${__/\/\/===\/=\/\_}.Size / 1GB, 2)
  ${____/\__/==\/=\/\} = [math]::Round(${__/\/\/===\/=\/\_}.FreeSpace / 1GB, 2)

  echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlADoAIAAkAGQAcgBpAHYAZQBMAGUAdAB0AGUAcgA=')))
  echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAGIAZQBsADoAIAAkAGQAcgBpAHYAZQBMAGEAYgBlAGwA')))
  echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA6ACAAJABkAHIAaQB2AGUAUwBpAHoAZQAgAEcAQgA=')))
  echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAZQAgAFMAcABhAGMAZQA6ACAAJABkAHIAaQB2AGUARgByAGUAZQBTAHAAYQBjAGUAIABHAEIA')))
  echo ""
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQBuAHQAaQB2AGkAcgB1AHMAIABEAGUAdABlAGMAdABpAG8AbgAgACgAYQB0AHQAZQBtAHAAaQBuAGcAIAB0AG8AIAByAGUAYQBkACAAZQB4AGMAbAB1AHMAaQBvAG4AcwAgAGEAcwAgAHcAZQBsAGwAKQA=')))
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
ls $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsATABNAFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwA='))) -ErrorAction SilentlyContinue


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATgBFAFQAIABBAEMAQwBPAFUATgBUAFMAIABJAG4AZgBvAA==')))
net accounts


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBFAEcASQBTAFQAUgBZACAAUwBFAFQAVABJAE4ARwBTACAAQwBIAEUAQwBLAA==')))

 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQB1AGQAaQB0ACAATABvAGcAIABTAGUAdAB0AGkAbgBnAHMA')))

if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
  gi -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
}
else {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAQQB1AGQAaQB0ACAATABvAGcAIABzAGUAdAB0AGkAbgBnAHMALAAgAG4AbwAgAHIAZQBnAGkAcwB0AHIAeQAgAGUAbgB0AHIAeQAgAGYAbwB1AG4AZAAuAA==')))
}

 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVwBpAG4AZABvAHcAcwAgAEUAdgBlAG4AdAAgAEYAbwByAHcAYQByAGQAIAAoAFcARQBGACkAIAByAGUAZwBpAHMAdAByAHkA')))
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
  gi HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
}
else {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAcwAgAGEAcgBlACAAbgBvAHQAIABiAGUAaQBuAGcAIABmAG8AdwBhAHIAZABlAGQALAAgAG4AbwAgAHIAZQBnAGkAcwB0AHIAeQAgAGUAbgB0AHIAeQAgAGYAbwB1AG4AZAAuAA==')))
}

 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATABBAFAAUwAgAEMAaABlAGMAawA=')))
if (Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAEwAQQBQAFMAXABDAFMARQBcAEEAZABtAHAAdwBkAC4AZABsAGwA')))) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABBAFAAUwAgAGQAbABsACAAZgBvAHUAbgBkACAAbwBuACAAdABoAGkAcwAgAG0AYQBjAGgAaQBuAGUAIABhAHQAIABDADoAXABQAHIAbwBnAHIAYQBtACAARgBpAGwAZQBzAFwATABBAFAAUwBcAEMAUwBFAFwA'))) -ForegroundColor Green }
elseif (Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwAgACgAeAA4ADYAKQBcAEwAQQBQAFMAXABDAFMARQBcAEEAZABtAHAAdwBkAC4AZABsAGwA'))) ) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABBAFAAUwAgAGQAbABsACAAZgBvAHUAbgBkACAAbwBuACAAdABoAGkAcwAgAG0AYQBjAGgAaQBuAGUAIABhAHQAIABDADoAXABQAHIAbwBnAHIAYQBtACAARgBpAGwAZQBzACAAKAB4ADgANgApAFwATABBAFAAUwBcAEMAUwBFAFwA'))) -ForegroundColor Green }
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABBAFAAUwAgAGQAbABsAHMAIABuAG8AdAAgAGYAbwB1AG4AZAAgAG8AbgAgAHQAaABpAHMAIABtAGEAYwBoAGkAbgBlAA=='))) }
if ((gp HKLM:\Software\Policies\Microsoft Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABBAFAAUwAgAHIAZQBnAGkAcwB0AHIAeQAgAGsAZQB5ACAAZgBvAHUAbgBkACAAbwBuACAAdABoAGkAcwAgAG0AYQBjAGgAaQBuAGUA'))) -ForegroundColor Green }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVwBEAGkAZwBlAHMAdAAgAEMAaABlAGMAawA=')))
${__/\_/===\/\/=\/=} = (gp HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential
switch (${__/\_/===\/\/=\/=}) {
  0 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAGwAdQBlACAAMAAgAGYAbwB1AG4AZAAuACAAUABsAGEAaQBuAC0AdABlAHgAdAAgAFAAYQBzAHMAdwBvAHIAZABzACAAYQByAGUAIABuAG8AdAAgAHMAdABvAHIAZQBkACAAaQBuACAATABTAEEAUwBTAA=='))) }
  1 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAGwAdQBlACAAMQAgAGYAbwB1AG4AZAAuACAAUABsAGEAaQBuAC0AdABlAHgAdAAgAFAAYQBzAHMAdwBvAHIAZABzACAAbQBhAHkAIABiAGUAIABzAHQAbwByAGUAZAAgAGkAbgAgAEwAUwBBAFMAUwA='))) -ForegroundColor red }
  Default { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHkAcwB0AGUAbQAgAHcAYQBzACAAdQBuAGEAYgBsAGUAIAB0AG8AIABmAGkAbgBkACAAdABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHIAZQBnAGkAcwB0AHIAeQAgAHYAYQBsAHUAZQA6ACAAVQBlAHMATABvAGcAbwBuAEMAcgBlAGQAZQBuAHQAaQBhAGwA'))) }
}

 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATABTAEEAIABQAHIAbwB0AGUAYwB0AGkAbwBuACAAQwBoAGUAYwBrAA==')))
${/======\_/==\_/==} = (gp HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
${_/\/\/\_/=\_/=\/=} = (gp HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPLBoot
switch (${/======\_/==\_/==}) {
  2 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AQQBzAFAAUABMADoAIAAyAC4AIABFAG4AYQBiAGwAZQBkACAAdwBpAHQAaABvAHUAdAAgAFUARQBGAEkAIABMAG8AYwBrAA=='))) }
  1 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AQQBzAFAAUABMADoAIAAxAC4AIABFAG4AYQBiAGwAZQBkACAAdwBpAHQAaAAgAFUARQBGAEkAIABMAG8AYwBrAA=='))) }
  0 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AQQBzAFAAUABMADoAIAAwAC4AIABMAFMAQQAgAFAAcgBvAHQAZQBjAHQAaQBvAG4AIABEAGkAcwBhAGIAbABlAGQALgAgAFQAcgB5ACAAbQBpAG0AaQBrAGEAdAB6AC4A'))) -ForegroundColor red }
  Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHkAcwB0AGUAbQAgAHcAYQBzACAAdQBuAGEAYgBsAGUAIAB0AG8AIABmAGkAbgBkACAAdABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHIAZQBnAGkAcwB0AHIAeQAgAHYAYQBsAHUAZQA6ACAAUgB1AG4AQQBzAFAAUABMACAALwAgAFIAdQBuAEEAcwBQAFAATABCAG8AbwB0AA=='))) }
}
if (${_/\/\/\_/=\_/=\/=}) { Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AQQBzAFAAUABMAEIAbwBvAHQAOgAgACQAUgB1AG4AQQBzAFAAUABMAEIAbwBvAHQA'))) }

 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwByAGUAZABlAG4AdABpAGEAbAAgAEcAdQBhAHIAZAAgAEMAaABlAGMAawA=')))
${/\______/==\_/\/\} = (gp HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags
switch (${/\______/==\_/\/\}) {
  2 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABzAGEAQwBmAGcARgBsAGEAZwBzACAAMgAuACAARQBuAGEAYgBsAGUAZAAgAHcAaQB0AGgAbwB1AHQAIABVAEUARgBJACAATABvAGMAawA='))) }
  1 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABzAGEAQwBmAGcARgBsAGEAZwBzACAAMQAuACAARQBuAGEAYgBsAGUAZAAgAHcAaQB0AGgAIABVAEUARgBJACAATABvAGMAawA='))) }
  0 { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABzAGEAQwBmAGcARgBsAGEAZwBzACAAMAAuACAATABzAGEAQwBmAGcARgBsAGEAZwBzACAARABpAHMAYQBiAGwAZQBkAC4A'))) -ForegroundColor red }
  Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGUAIABzAHkAcwB0AGUAbQAgAHcAYQBzACAAdQBuAGEAYgBsAGUAIAB0AG8AIABmAGkAbgBkACAAdABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAHIAZQBnAGkAcwB0AHIAeQAgAHYAYQBsAHUAZQA6ACAATABzAGEAQwBmAGcARgBsAGEAZwBzAA=='))) }
}

 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBhAGMAaABlAGQAIABXAGkAbgBMAG8AZwBvAG4AIABDAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABDAGgAZQBjAGsA')))
if (Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))) {
  (gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA=='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBBAEMASABFAEQATABPAEcATwBOAFMAQwBPAFUATgBUAA==')))).CACHEDLOGONSCOUNT
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHcAZQB2AGUAcgAsACAAbwBuAGwAeQAgAHQAaABlACAAUwBZAFMAVABFAE0AIAB1AHMAZQByACAAYwBhAG4AIAB2AGkAZQB3ACAAdABoAGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABoAGUAcgBlADoAIABIAEsARQBZAF8ATABPAEMAQQBMAF8ATQBBAEMASABJAE4ARQBcAFMARQBDAFUAUgBJAFQAWQBcAEMAYQBjAGgAZQA=')))
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwByACwAIAB1AHMAaQBuAGcAIABtAGkAbQBpAGsAYQB0AHoAIABsAHMAYQBkAHUAbQBwADoAOgBjAGEAYwBoAGUA')))
}

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQBkAGQAaQB0AG8AbgBhAGwAIABXAGkAbgBsAG8AZwBvAG4AIABDAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABDAGgAZQBjAGsA')))

(gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))).DefaultDomainName
(gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))).DefaultUserName
(gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))).DefaultPassword
(gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))).AltDefaultDomainName
(gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))).AltDefaultUserName
(gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAVwBpAG4AbABvAGcAbwBuAA==')))).AltDefaultPassword


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBEAEMATQBhAG4AIABTAGUAdAB0AGkAbgBnAHMAIABDAGgAZQBjAGsA')))

if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFUAUwBFAFIAUABSAE8ARgBJAEwARQBcAGEAcABwAGQAYQB0AGEAXABMAG8AYwBhAGwAXABNAGkAYwByAG8AcwBvAGYAdABcAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAEMAbwBuAG4AZQBjAHQAaQBvAG4AIABNAGEAbgBhAGcAZQByAFwAUgBEAEMATQBhAG4ALgBzAGUAdAB0AGkAbgBnAHMA')))) {
  Write-Host "RDCMan Settings Found at: $($env:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ForegroundColor Red
}
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAUgBDAEQATQBhAG4ALgBTAGUAdAB0AGkAbgBnAHMAIABmAG8AdQBuAGQALgA='))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBEAFAAIABTAGEAdgBlAGQAIABDAG8AbgBuAGUAYwB0AGkAbwBuAHMAIABDAGgAZQBjAGsA')))

Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAF8AVQBzAGUAcgBzAA==')))
ndr -PSProvider Registry -Name HKU -Root HKEY_USERS
ls HKU:\ -ErrorAction SilentlyContinue | % {
  
  ${_/=\__/\___/=\__/} = $_.Name.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAFUAUwBFAFIAUwBcAA=='))), "")
  if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsARQBZAF8AVQBTAEUAUgBTAFwAJABIAEsAVQBTAEkARABcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABDAGwAaQBlAG4AdABcAEQAZQBmAGEAdQBsAHQA')))) {
    Write-Host "Server Found: $((gp $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsARQBZAF8AVQBTAEUAUgBTAFwAJABIAEsAVQBTAEkARABcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABDAGwAaQBlAG4AdABcAEQAZQBmAGEAdQBsAHQA'))) -Name MRU0).MRU0)"
  }
  else { Write-Host "Not found for $($_.Name)" }
}

Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA=')))
if (Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsARQBZAF8AQwBVAFIAUgBFAE4AVABfAFUAUwBFAFIAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABEAGUAZgBhAHUAbAB0AA==')))) {
  Write-Host "Server Found: $((gp $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsARQBZAF8AQwBVAFIAUgBFAE4AVABfAFUAUwBFAFIAXABTAG8AZgB0AHcAYQByAGUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABEAGUAZgBhAHUAbAB0AA=='))) -Name MRU0).MRU0)"
}
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABDAGwAaQBlAG4AdAAgAG4AbwB0ACAAZgBvAHUAbgBkACAAaQBuACAASABDAEsAVQA='))) }

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUAB1AHQAdAB5ACAAUwB0AG8AcgBlAGQAIABDAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABDAGgAZQBjAGsA')))

if (Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions) {
  ls HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions | % {
    ${/=====\/===\/===\} = Split-Path $_.Name -Leaf
    Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHkAOgAgACQAUgBlAGcASwBlAHkATgBhAG0AZQA=')))
    @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABOAGEAbQBlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHIAdABOAHUAbQBiAGUAcgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMASwBlAHkARgBpAGwAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHIAdABGAG8AcgB3AGEAcgBkAGkAbgBnAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdABpAG8AbgBTAGgAYQByAGkAbgBnAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFUAcwBlAHIAbgBhAG0AZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFAAYQBzAHMAdwBvAHIAZAA=')))) | % {
      Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABfACAAOgA=')))
      Write-Host "$((gp  HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\${/=====\/===\/===\}).$_)"
    }
  }
}
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAB1AHQAdAB5ACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAZgBvAHUAbgBkACAAaQBuACAASABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUwBpAG0AbwBuAFQAYQB0AGgAYQBtAFwAUAB1AFQAVABZAFwAUwBlAHMAcwBpAG8AbgBzAA=='))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBTAEgAIABLAGUAeQAgAEMAaABlAGMAawBzAA==')))
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASQBmACAAZgBvAHUAbgBkADoA')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbABvAGcALgByAG8AcABuAG8AcAAuAGMAbwBtAC8AZQB4AHQAcgBhAGMAdABpAG4AZwAtAHMAcwBoAC0AcAByAGkAdgBhAHQAZQAtAGsAZQB5AHMALQBmAHIAbwBtAC0AdwBpAG4AZABvAHcAcwAtADEAMAAtAHMAcwBoAC0AYQBnAGUAbgB0AC8A'))) -ForegroundColor Yellow
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAUAB1AHQAdAB5ACAAUwBTAEgAIABLAE4ATwBXAE4AIABIAE8AUwBUAFMA')))
if (Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys) { 
  Write-Host "$((gi -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)"
}
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAcAB1AHQAdAB5ACAAcwBzAGgAIABrAGUAeQBzACAAZgBvAHUAbgBkAA=='))) }

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABPAHAAZQBuAFMAUwBIACAASwBlAHkAcwA=')))
if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAFMASAAgAGsAZQB5AHMAIABmAG8AdQBuAGQALgAgAFQAcgB5ACAAdABoAGkAcwAgAGYAbwByACAAZABlAGMAcgB5AHAAdABpAG8AbgA6ACAAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwByAG8AcABuAG8AcAAvAHcAaQBuAGQAbwB3AHMAXwBzAHMAaABhAGcAZQBuAHQAXwBlAHgAdAByAGEAYwB0AA=='))) -ForegroundColor Yellow }
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAATwBwAGUAbgBTAFMASAAgAEsAZQB5AHMAIABmAG8AdQBuAGQALgA='))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABXAGkAbgBWAE4AQwAgAFAAYQBzAHMAdwBvAHIAZABzAA==')))
if ( Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATwBSAEwAXABXAGkAbgBWAE4AQwAzAFwAUABhAHMAcwB3AG8AcgBkAA==')))) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABXAGkAbgBWAE4AQwAgAGYAbwB1AG4AZAAgAGEAdAAgAEgASwBDAFUAOgBcAFMAbwBmAHQAdwBhAHIAZQBcAE8AUgBMAFwAVwBpAG4AVgBOAEMAMwBcAFAAYQBzAHMAdwBvAHIAZAA='))) }else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAVwBpAG4AVgBOAEMAIABmAG8AdQBuAGQALgA='))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABTAE4ATQBQACAAUABhAHMAcwB3AG8AcgBkAHMA')))
if ( Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBZAFMAVABFAE0AXABDAHUAcgByAGUAbgB0AEMAbwBuAHQAcgBvAGwAUwBlAHQAXABTAGUAcgB2AGkAYwBlAHMAXABTAE4ATQBQAA=='))) ) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBOAFAATQAgAEsAZQB5ACAAZgBvAHUAbgBkACAAYQB0ACAASABLAEwATQA6AFwAUwBZAFMAVABFAE0AXABDAHUAcgByAGUAbgB0AEMAbwBuAHQAcgBvAGwAUwBlAHQAXABTAGUAcgB2AGkAYwBlAHMAXABTAE4ATQBQAA=='))) }else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAUwBOAFAATQAgAGYAbwB1AG4AZAAuAA=='))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABUAGkAZwBoAHQAVgBOAEMAIABQAGEAcwBzAHcAbwByAGQAcwA=')))
if ( Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAVABpAGcAaAB0AFYATgBDAFwAUwBlAHIAdgBlAHIA')))) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGcAaAB0AFYATgBDACAAawBlAHkAIABmAG8AdQBuAGQAIABhAHQAIABIAEsAQwBVADoAXABTAG8AZgB0AHcAYQByAGUAXABUAGkAZwBoAHQAVgBOAEMAXABTAGUAcgB2AGUAcgA='))) }else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAVABpAGcAaAB0AFYATgBDACAAZgBvAHUAbgBkAC4A'))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVQBBAEMAIABTAGUAdAB0AGkAbgBnAHMA')))
if ((gp HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 1) {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGEAYgBsAGUATABVAEEAIABpAHMAIABlAHEAdQBhAGwAIAB0AG8AIAAxAC4AIABQAGEAcgB0ACAAbwByACAAYQBsAGwAIABvAGYAIAB0AGgAZQAgAFUAQQBDACAAYwBvAG0AcABvAG4AZQBuAHQAcwAgAGEAcgBlACAAbwBuAC4A')))
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAYgBhAHMAaQBjAC0AdQBhAGMALQBiAHkAcABhAHMAcwAtAGYAdQBsAGwALQBmAGkAbABlAC0AcwB5AHMAdABlAG0ALQBhAGMAYwBlAHMAcwA='))) -ForegroundColor Yellow
}
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGEAYgBsAGUATABVAEEAIAB2AGEAbAB1AGUAIABuAG8AdAAgAGUAcQB1AGEAbAAgAHQAbwAgADEA'))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBlAGMAZQBuAHQAbAB5ACAAUgB1AG4AIABDAG8AbQBtAGEAbgBkAHMAIAAoAFcASQBOACsAUgApAA==')))

ls HKU:\ -ErrorAction SilentlyContinue | % {
  
  ${_/=\__/\___/=\__/} = $_.Name.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAFUAUwBFAFIAUwBcAA=='))), "")
  ${/====\/===\/==\_/} = (gi $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAFUAOgBcACQAXwBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEUAeABwAGwAbwByAGUAcgBcAFIAdQBuAE0AUgBVAA=='))) -ErrorAction SilentlyContinue).Property
  ${_/=\__/\___/=\__/} | % {
    if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAFUAOgBcACQAXwBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEUAeABwAGwAbwByAGUAcgBcAFIAdQBuAE0AUgBVAA==')))) {
      Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8AEgASwBVACAAUgBlAGMAZQBuAHQAbAB5ACAAUgB1AG4AIABDAG8AbQBtAGEAbgBkAHMA')))
      foreach (${/======\/=\_/==\/} in ${/====\/===\/==\_/}) {
        Write-Host "$((gi $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAFUAOgBcACQAXwBcAFMATwBGAFQAVwBBAFIARQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBuAHQAVgBlAHIAcwBpAG8AbgBcAEUAeABwAGwAbwByAGUAcgBcAFIAdQBuAE0AUgBVAA==')))-ErrorAction SilentlyContinue).getValue(${/======\/=\_/==\/}))" 
      }
    }
  }
}

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8AEgASwBDAFUAIABSAGUAYwBlAG4AdABsAHkAIABSAHUAbgAgAEMAbwBtAG0AYQBuAGQAcwA=')))
${/====\/===\/==\_/} = (gi $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwARQB4AHAAbABvAHIAZQByAFwAUgB1AG4ATQBSAFUA'))) -ErrorAction SilentlyContinue).Property
foreach (${/======\/=\_/==\/} in ${/====\/===\/==\_/}) {
  Write-Host "$((gi $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwARQB4AHAAbABvAHIAZQByAFwAUgB1AG4ATQBSAFUA')))-ErrorAction SilentlyContinue).getValue(${/======\/=\_/==\/}))"
}

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQBsAHcAYQB5AHMAIABJAG4AcwB0AGEAbABsACAARQBsAGUAdgBhAHQAZQBkACAAQwBoAGUAYwBrAA==')))
 
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAVwBpAG4AZABvAHcAcwAgAEkAbgBzAHQAYQBsAGwAZQByACAAUgBlAGcAaQBzAHQAcgB5ACAAKAB3AGkAbABsACAAcABvAHAAdQBsAGEAdABlACAAaQBmACAAdABoAGUAIABrAGUAeQAgAGUAeABpAHMAdABzACkA')))
if ((gp HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwASQBuAHMAdABhAGwAbABlAHIAKQAuAEEAbAB3AGEAeQBzAEkAbgBzAHQAYQBsAGwARQBsAGUAdgBhAHQAZQBkACAAPQAgADEA'))) -ForegroundColor red
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAIABtAHMAZgB2AGUAbgBvAG0AIABtAHMAaQAgAHAAYQBjAGsAYQBnAGUAIAB0AG8AIABlAHMAYwBhAGwAYQB0AGUA'))) -ForegroundColor red
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAbQBlAHQAYQBzAHAAbABvAGkAdAAtAHAAYQB5AGwAbwBhAGQAcwA='))) -ForegroundColor Yellow
}
 
if ((gp HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) { 
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwASQBuAHMAdABhAGwAbABlAHIAKQAuAEEAbAB3AGEAeQBzAEkAbgBzAHQAYQBsAGwARQBsAGUAdgBhAHQAZQBkACAAPQAgADEA'))) -ForegroundColor red
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAIABtAHMAZgB2AGUAbgBvAG0AIABtAHMAaQAgAHAAYQBjAGsAYQBnAGUAIAB0AG8AIABlAHMAYwBhAGwAYQB0AGUA'))) -ForegroundColor red
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAbQBlAHQAYQBzAHAAbABvAGkAdAAtAHAAYQB5AGwAbwBhAGQAcwA='))) -ForegroundColor Yellow
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUABvAHcAZQByAFMAaABlAGwAbAAgAEkAbgBmAG8A')))

(gp registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine).PowerShellVersion | % {
  Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgACQAXwAgAGEAdgBhAGkAbABhAGIAbABlAA==')))
}
(gp registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine).PowerShellVersion | % {
  Write-Host  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgACQAXwAgAGEAdgBhAGkAbABhAGIAbABlAA==')))
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUABvAHcAZQByAFMAaABlAGwAbAAgAFIAZQBnAGkAcwB0AHIAeQAgAFQAcgBhAG4AcwBjAHIAaQBwAHQAIABDAGgAZQBjAGsA')))

if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  gi HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  gi HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  gi HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  gi HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
 

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUABvAHcAZQByAFMAaABlAGwAbAAgAE0AbwBkAHUAbABlACAATABvAGcAIABDAGgAZQBjAGsA')))
if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  gi HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  gi HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  gi HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  gi HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
 

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUABvAHcAZQByAFMAaABlAGwAbAAgAFMAYwByAGkAcAB0ACAAQgBsAG8AYwBrACAATABvAGcAIABDAGgAZQBjAGsA')))
 
if ( Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  gi HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  gi HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  gi HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  gi HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVwBTAFUAUwAgAGMAaABlAGMAawAgAGYAbwByACAAaAB0AHQAcAAgAGEAbgBkACAAVQBzAGUAVwBBAFMAZQByAHYAZQByACAAPQAgADEALAAgAGkAZgAgAHQAcgB1AGUALAAgAG0AaQBnAGgAdAAgAGIAZQAgAHYAdQBsAG4AZQByAGEAYgBsAGUAIAB0AG8AIABlAHgAcABsAG8AaQB0AA==')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAdwBzAHUAcwA='))) -ForegroundColor Yellow
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) {
  gi HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
}
if ((gp HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAVwBVAFMAZQByAHYAZQByAA=='))) -ErrorAction SilentlyContinue).UseWUServer) {
  (gp HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAVwBVAFMAZQByAHYAZQByAA==')))).UseWUServer
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzACAASABLAEMAVQAgAC8AIABIAEsATABNAA==')))

${/====\/===\/==\_/} = (gi $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA=='))) -ErrorAction SilentlyContinue).Property
foreach (${/======\/=\_/==\/} in ${/====\/===\/==\_/}) {
  Write-Host "${/======\/=\_/==\/} - $((gi $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA==')))-ErrorAction SilentlyContinue).getValue(${/======\/=\_/==\/}))"
}
 
${/====\/===\/==\_/} = (gi $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA=='))) -ErrorAction SilentlyContinue).Property
foreach (${/======\/=\_/==\/} in ${/====\/===\/==\_/}) {
  Write-Host "${/======\/=\_/==\/} - $((gi $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA==')))-ErrorAction SilentlyContinue).getValue(${/======\/=\_/==\/}))"
}




Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBVAE4ATgBJAE4ARwAgAFAAUgBPAEMARQBTAFMARQBTAA==')))


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAdQBzAGUAcgAgAHAAZQByAG0AaQBzAHMAaQBvAG4AcwAgAG8AbgAgAHIAdQBuAG4AaQBuAGcAIABwAHIAbwBjAGUAcwBzAGUAcwA=')))
ps | select Path -Unique | % { ___/=\_/\___/\/\/= -Target $_.path }



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwB5AHMAdABlAG0AIABwAHIAbwBjAGUAcwBzAGUAcwA=')))
saps tasklist -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB2ACAALwBmAGkAIAAiAHUAcwBlAHIAbgBhAG0AZQAgAGUAcQAgAHMAeQBzAHQAZQBtACIA'))) -Wait -NoNewWindow



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBFAFIAVgBJAEMARQAgAHAAYQB0AGgAIAB2AHUAbABuAGUAcgBhAGIAbABlACAAYwBoAGUAYwBrAA==')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIAB2AHUAbABuAGUAcgBhAGIAbABlACAAcwBlAHIAdgBpAGMAZQAgAC4AZQB4AGUA')))

${_/=\/\___/=\___/=} = @{}
gwmi Win32_Service | ? { $_.PathName -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlACoA'))) } | % {
  ${/==\/=\/====\_/==} = ($_.PathName -split $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/ADwAPQBcAC4AZQB4AGUAXABiACkA'))))[0].Trim('"')
  ${_/=\/\___/=\___/=}[${/==\/=\/====\_/==}] = $_.Name
}
foreach ( ${__/\/===\_/=====\} in (${_/=\/\___/=\___/=} | select -Unique).GetEnumerator()) {
  ___/=\_/\___/\/\/= -Target ${__/\/===\_/=====\}.Name -ServiceName ${__/\/===\_/=====\}.Value
}



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABVAG4AcQB1AG8AdABlAGQAIABTAGUAcgB2AGkAYwBlACAAUABhAHQAaABzAA==')))



_/==\__/\_/\_/\_/\



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAUwBlAHIAdgBpAGMAZQAgAFIAZQBnAGkAcwB0AHIAeQAgAFAAZQByAG0AaQBzAHMAaQBvAG4AcwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAHcAaQBsAGwAIAB0AGEAawBlACAAcwBvAG0AZQAgAHQAaQBtAGUALgA=')))

ls $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwB5AHMAdABlAG0AXABDAHUAcgByAGUAbgB0AEMAbwBuAHQAcgBvAGwAUwBlAHQAXABzAGUAcgB2AGkAYwBlAHMAXAA='))) | % {
  $target = $_.Name.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABrAGwAbQA6AA=='))))
  ___/=\_/\___/\/\/= -Target $target
}



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBDAEgARQBEAFUATABFAEQAIABUAEEAUwBLAFMAIAB2AHUAbABuAGUAcgBhAGIAbABlACAAYwBoAGUAYwBrAA==')))


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVABlAHMAdABpAG4AZwAgAGEAYwBjAGUAcwBzACAAdABvACAAYwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHQAYQBzAGsAcwA=')))
if (ls $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHQAYQBzAGsAcwA='))) -ErrorAction SilentlyContinue) {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAIABjAG8AbgBmAGkAcgBtAGUAZAAsACAAbQBhAHkAIABuAGUAZQBkACAAZgB1AHQAaABlAHIAIABpAG4AdgBlAHMAdABpAGcAYQB0AGkAbwBuAA==')))
  ls $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAHQAYQBzAGsAcwA=')))
}
else {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAYQBkAG0AaQBuACAAYQBjAGMAZQBzAHMAIAB0AG8AIABzAGMAaABlAGQAdQBsAGUAZAAgAHQAYQBzAGsAcwAgAGYAbwBsAGQAZQByAC4A')))
  Get-ScheduledTask | ? { $_.TaskPath -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAqAA=='))) } | % {
    ${_/=\/\__/\/\/\/==} = $_.Actions.Execute
    if (${_/=\/\__/\/\/\/==} -ne $null) {
      foreach (${/=\___/=\_/\____/} in ${_/=\/\__/\/\/\/==}) {
        if (${/=\___/=\_/\____/} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQB3AGkAbgBkAGkAcgAlACoA')))) { ${/=\___/=\_/\____/} = ${/=\___/=\_/\____/}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQB3AGkAbgBkAGkAcgAlAA=='))), $Env:windir) }
        elseif (${/=\___/=\_/\____/} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBTAHkAcwB0AGUAbQBSAG8AbwB0ACUAKgA=')))) { ${/=\___/=\_/\____/} = ${/=\___/=\_/\____/}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBTAHkAcwB0AGUAbQBSAG8AbwB0ACUA'))), $Env:windir) }
        elseif (${/=\___/=\_/\____/} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBsAG8AYwBhAGwAYQBwAHAAZABhAHQAYQAlACoA')))) { ${/=\___/=\_/\____/} = ${/=\___/=\_/\____/}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBsAG8AYwBhAGwAYQBwAHAAZABhAHQAYQAlAA=='))), $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFUAcwBlAHIAUAByAG8AZgBpAGwAZQBcAGEAcABwAGQAYQB0AGEAXABsAG8AYwBhAGwA')))) }
        elseif (${/=\___/=\_/\____/} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBhAHAAcABkAGEAdABhACUAKgA=')))) { ${/=\___/=\_/\____/} = ${/=\___/=\_/\____/}.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBsAG8AYwBhAGwAYQBwAHAAZABhAHQAYQAlAA=='))), $env:Appdata) }
        ${/=\___/=\_/\____/} = ${/=\___/=\_/\____/}.Replace('"', '')
        ___/=\_/\___/\/\/= -Target ${/=\___/=\_/\____/}
        Write-Host "`n"
        Write-Host "TaskName: $($_.TaskName)"
        Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAC0ALQAtAC0ALQAtAC0ALQAtAC0ALQA=')))
        [pscustomobject]@{
          LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
          NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
          Status     = $_.State
          Command    = $_.Actions.execute
          Arguments  = $_.Actions.Arguments 
        } | Write-Host
      } 
    }
  }
}



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBUAEEAUgBUAFUAUAAgAEEAUABQAEwASQBDAEEAVABJAE8ATgBTACAAVgB1AGwAbgBlAHIAYQBiAGwAZQAgAEMAaABlAGMAawA=')))
$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrACAAaQBmACAAeQBvAHUAIABjAGEAbgAgAG0AbwBkAGkAZgB5ACAAYQBuAHkAIABiAGkAbgBhAHIAeQAgAHQAaABhAHQAIABpAHMAIABnAG8AaQBuAGcAIAB0AG8AIABiAGUAIABlAHgAZQBjAHUAdABlAGQAIABiAHkAIABhAGQAbQBpAG4AIABvAHIAIABpAGYAIAB5AG8AdQAgAGMAYQBuACAAaQBtAHAAZQByAHMAbwBuAGEAdABlACAAYQAgAG4AbwB0ACAAZgBvAHUAbgBkACAAYgBpAG4AYQByAHkA')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAcgB1AG4ALQBhAHQALQBzAHQAYQByAHQAdQBwAA=='))) -ForegroundColor Yellow

@($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwARABvAGMAdQBtAGUAbgB0AHMAIABhAG4AZAAgAFMAZQB0AHQAaQBuAGcAcwBcAEEAbABsACAAVQBzAGUAcgBzAFwAUwB0AGEAcgB0ACAATQBlAG4AdQBcAFAAcgBvAGcAcgBhAG0AcwBcAFMAdABhAHIAdAB1AHAA'))),
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwARABvAGMAdQBtAGUAbgB0AHMAIABhAG4AZAAgAFMAZQB0AHQAaQBuAGcAcwBcACQAZQBuAHYAOgBVAHMAZQByAG4AYQBtAGUAXABTAHQAYQByAHQAIABNAGUAbgB1AFwAUAByAG8AZwByAGEAbQBzAFwAUwB0AGEAcgB0AHUAcAA='))), 
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFMAdABhAHIAdAAgAE0AZQBuAHUAXABQAHIAbwBnAHIAYQBtAHMAXABTAHQAYQByAHQAdQBwAA=='))), 
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AEEAcABwAGQAYQB0AGEAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABTAHQAYQByAHQAIABNAGUAbgB1AFwAUAByAG8AZwByAGEAbQBzAFwAUwB0AGEAcgB0AHUAcAA=')))) | % {
  if (Test-Path $_) {
    
    ___/=\_/\___/\/\/= $_
    ls -Recurse -Force -Path $_ | % {
      ${__/=\_/==\__/=\_/} = $_.FullName
      if (Test-Path ${__/=\_/==\__/=\_/}) { 
        ___/=\_/\___/\/\/= -Target ${__/=\_/==\__/=\_/}
      }
    }
  }
}
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBUAEEAUgBUAFUAUAAgAEEAUABQAFMAIABSAGUAZwBpAHMAdAByAHkAIABDAGgAZQBjAGsA')))

@($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsATABNAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4A'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsATABNAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4ATwBuAGMAZQA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsAQwBVAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4A'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBIAEsAQwBVAFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4ATwBuAGMAZQA=')))) | % {
  
  ${_/\_/=\_/===\_/\_} = $_
  (gi $_) | % {
    ${__/\/\/=\______/=} = $_.property
    ${__/\/\/=\______/=} | % {
      ___/=\_/\___/\/\/= ((gp -Path ${_/\_/=\_/===\_/\_}).$_ -split $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAA/ADwAPQBcAC4AZQB4AGUAXABiACkA'))))[0].Trim('"')
    }
  }
}





Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASQBOAFMAVABBAEwATABFAEQAIABBAFAAUABMAEkAQwBBAFQASQBPAE4AUwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGEAdABpAG4AZwAgAGwAaQBzAHQAIABvAGYAIABpAG4AcwB0AGEAbABsAGUAZAAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgBzAA==')))

Get-CimInstance -class win32_Product | select Name, Version | 
% {
  Write-Host $($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwAH0AIAA6ACAAewAxAH0A'))) -f $_.Name, $_.Version)  
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATABPAE8ASwBJAE4ARwAgAEYATwBSACAAQgBBAFMASAAuAEUAWABFAA==')))
ls C:\Windows\WinSxS\ -Filter "amd64_microsoft-windows-lxss-bash*" | % {
  Write-Host $((ls $_.FullName -Recurse -Filter "*bash.exe*").FullName)
}
@($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAHMAaAAuAGUAeABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBzAGwALgBlAHgAZQA=')))) | % { Write-Host $((ls C:\Windows\System32\ -Filter $_).FullName) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATABPAE8ASwBJAE4ARwAgAEYATwBSACAAUwBDAEMATQAgAEMATABJAEUATgBUAA==')))
${/====\/==\_/===\_} = gwmi -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGMAYwBtAFwAYwBsAGkAZQBuAHQAUwBEAEsA'))) -Class CCM_Application -Property * -ErrorAction SilentlyContinue | select Name, SoftwareVersion
if (${/====\/==\_/===\_}) { ${/====\/==\_/===\_} }
elseif (Test-Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAEMAQwBNAFwAUwBDAEMAbABpAGUAbgB0AC4AZQB4AGUA')))) { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBDAEMATQAgAEMAbABpAGUAbgB0ACAAZgBvAHUAbgBkACAAYQB0ACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAEMAQwBNAFwAUwBDAEMAbABpAGUAbgB0AC4AZQB4AGUA'))) -ForegroundColor Cyan }
else { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAIABJAG4AcwB0AGEAbABsAGUAZAAuAA=='))) }



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATgBFAFQAVwBPAFIASwAgAEkATgBGAE8AUgBNAEEAVABJAE8ATgA=')))

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASABPAFMAVABTACAARgBJAEwARQA=')))

Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAIABjAG8AbgB0AGUAbgB0ACAAbwBmACAAZQB0AGMAXABoAG8AcwB0AHMAIABmAGkAbABlAA==')))
gc $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwA6AFwAdwBpAG4AZABvAHcAcwBcAHMAeQBzAHQAZQBtADMAMgBcAGQAcgBpAHYAZQByAHMAXABlAHQAYwBcAGgAbwBzAHQAcwA=')))

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASQBQACAASQBOAEYATwBSAE0AQQBUAEkATwBOAA==')))


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASQBwAGMAbwBuAGYAaQBnACAAQQBMAEwA')))
saps ipconfig.exe -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBhAGwAbAA='))) -Wait -NoNewWindow


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAARABOAFMAIABDAGEAYwBoAGUA')))
ipconfig /displaydns | sls $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQA'))) | % { Write-Host $($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwAH0A'))) -f $_) }
 
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATABJAFMAVABFAE4ASQBOAEcAIABQAE8AUgBUAFMA')))


saps NETSTAT.EXE -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQBhAG4AbwA='))) -Wait -NoNewWindow


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQBSAFAAIABUAGEAYgBsAGUA')))


saps arp -ArgumentList "-A" -Wait -NoNewWindow

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBvAHUAdABlAHMA')))


saps route -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbgB0AA=='))) -Wait -NoNewWindow

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATgBlAHQAdwBvAHIAawAgAEEAZABhAHAAdABlAHIAIABpAG4AZgBvAA==')))


Get-NetAdapter | % { 
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAC0ALQAtAC0ALQAtAC0ALQA=')))
  Write-Host $_.Name
  Write-Host $_.InterfaceDescription
  Write-Host $_.ifIndex
  Write-Host $_.Status
  Write-Host $_.MacAddress
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAC0ALQAtAC0ALQAtAC0ALQA=')))
} 


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABXAGkARgBpACAAcABhAHMAcwB3AG8AcgBkAHMA')))


((netsh.exe wlan show profiles) -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABzAHsAMgAsAH0AOgBcAHMA')))).replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAgACAAIABBAGwAbAAgAFUAcwBlAHIAIABQAHIAbwBmAGkAbABlACAAIAAgACAAIAA6ACAA'))), "") | % {
  netsh wlan show profile name="$_" key=clear 
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAARQBuAGEAYgBsAGUAZAAgAGYAaQByAGUAdwBhAGwAbAAgAHIAdQBsAGUAcwAgAC0AIABkAGkAcwBwAGwAYQB5AGkAbgBnACAAYwBvAG0AbQBhAG4AZAAgAG8AbgBsAHkAIAAtACAAaQB0ACAAYwBhAG4AIABvAHYAZQByAHcAcgBpAHQAZQAgAHQAaABlACAAZABpAHMAcABsAGEAeQAgAGIAdQBmAGYAZQByAA==')))
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAcwBoAG8AdwAgAGEAbABsACAAcgB1AGwAZQBzACAAdwBpAHQAaAA6ACAAbgBlAHQAcwBoACAAYQBkAHYAZgBpAHIAZQB3AGEAbABsACAAZgBpAHIAZQB3AGEAbABsACAAcwBoAG8AdwAgAHIAdQBsAGUAIABkAGkAcgA9AGkAbgAgAG4AYQBtAGUAPQBhAGwAbAA=')))


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBNAEIAIABTAEgAQQBSAEUAUwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAGwAbAAgAGUAbgB1AG0AZQByAGEAdABlACAAUwBNAEIAIABTAGgAYQByAGUAcwAgAGEAbgBkACAAQQBjAGMAZQBzAHMAIABpAGYAIABhAG4AeQAgAGEAcgBlACAAYQB2AGEAaQBsAGEAYgBsAGUA'))) 

Get-SmbShare | Get-SmbShareAccess | % {
  ${/===\/\_/=\_/====} = $_
  whoami.exe /groups /fo csv | ConvertFrom-Csv | select -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwACAAbgBhAG0AZQA='))) | % {
    if (${/===\/\_/=\_/====}.AccountName -like $_ -and (${/===\/\_/=\_/====}.AccessRight -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbAA='))) -or $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBnAGUA')))) -and ${/===\/\_/=\_/====}.AccessControlType -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA=='))) ) {
      Write-Host -ForegroundColor red "$(${/===\/\_/=\_/====}.AccountName) has $(${/===\/\_/=\_/====}.AccessRight) to $(${/===\/\_/=\_/====}.Name)"
    }
  }
}



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVQBTAEUAUgAgAEkATgBGAE8A')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9ACAAfAB8ACAARwBlAG4AZQByAGEAdABpAG4AZwAgAEwAaQBzAHQAIABvAGYAIABhAGwAbAAgAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwAsACAAVQBzAGUAcgBzACAAYQBuAGQAIABCAGEAYwBrAHUAcAAgAE8AcABlAHIAYQB0AG8AcgBzACAAKABpAGYAIABhAG4AeQAgAGUAeABpAHMAdAApAA==')))

@($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOAEkAUwBUAFIAQQBUAE8AUgBTAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAUgBTAA==')))) | % {
  Write-Host $_
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAC0ALQAtAC0ALQA=')))
  saps net -ArgumentList $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGcAcgBvAHUAcAAgACQAXwA='))) -Wait -NoNewWindow
}
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBBAEMASwBVAFAAIABPAFAARQBSAEEAVABPAFIAUwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAtAC0ALQAtAC0ALQA=')))
saps net -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGcAcgBvAHUAcAAgACIAQgBhAGMAawB1AHAAIABPAHAAZQByAGEAdABvAHIAcwAiAA=='))) -Wait -NoNewWindow


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVQBTAEUAUgAgAEQASQBSAEUAQwBUAE8AUgBZACAAQQBDAEMARQBTAFMAIABDAEgARQBDAEsA')))
ls C:\Users\* | % {
  if (ls $_.FullName -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor red "Read Access to $($_.FullName)"
  }
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVwBIAE8AQQBNAEkAIABJAE4ARgBPAA==')))
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrACAAVABvAGsAZQBuACAAYQBjAGMAZQBzAHMAIABoAGUAcgBlADoAIABoAHQAdABwAHMAOgAvAC8AYgBvAG8AawAuAGgAYQBjAGsAdAByAGkAYwBrAHMALgB4AHkAegAvAHcAaQBuAGQAbwB3AHMALQBoAGEAcgBkAGUAbgBpAG4AZwAvAHcAaQBuAGQAbwB3AHMALQBsAG8AYwBhAGwALQBwAHIAaQB2AGkAbABlAGcAZQAtAGUAcwBjAGEAbABhAHQAaQBvAG4ALwBwAHIAaQB2AGkAbABlAGcAZQAtAGUAcwBjAGEAbABhAHQAaQBvAG4ALQBhAGIAdQBzAGkAbgBnAC0AdABvAGsAZQBuAHMA'))) -ForegroundColor yellow
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrACAAaQBmACAAeQBvAHUAIABhAHIAZQAgAGkAbgBzAGkAZABlACAAdABoAGUAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMAIABnAHIAbwB1AHAAIABvAHIAIABpAGYAIAB5AG8AdQAgAGgAYQB2AGUAIABlAG4AYQBiAGwAZQBkACAAYQBuAHkAIAB0AG8AawBlAG4AIAB0AGgAYQB0ACAAYwBhAG4AIABiAGUAIAB1AHMAZQAgAHQAbwAgAGUAcwBjAGEAbABhAHQAZQAgAHAAcgBpAHYAaQBsAGUAZwBlAHMAIABsAGkAawBlACAAUwBlAEkAbQBwAGUAcgBzAG8AbgBhAHQAZQBQAHIAaQB2AGkAbABlAGcAZQAsACAAUwBlAEEAcwBzAGkAZwBuAFAAcgBpAG0AYQByAHkAUAByAGkAdgBpAGwAZQBnAGUALAAgAFMAZQBUAGMAYgBQAHIAaQB2AGkAbABlAGcAZQAsACAAUwBlAEIAYQBjAGsAdQBwAFAAcgBpAHYAaQBsAGUAZwBlACwAIABTAGUAUgBlAHMAdABvAHIAZQBQAHIAaQB2AGkAbABlAGcAZQAsACAAUwBlAEMAcgBlAGEAdABlAFQAbwBrAGUAbgBQAHIAaQB2AGkAbABlAGcAZQAsACAAUwBlAEwAbwBhAGQARAByAGkAdgBlAHIAUAByAGkAdgBpAGwAZQBnAGUALAAgAFMAZQBUAGEAawBlAE8AdwBuAGUAcgBzAGgAaQBwAFAAcgBpAHYAaQBsAGUAZwBlACwAIABTAGUARABlAGIAYgB1AGcAUAByAGkAdgBpAGwAZQBnAGUA')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAdQBzAGUAcgBzAC0AYQBuAGQALQBnAHIAbwB1AHAAcwA='))) -ForegroundColor Yellow
saps whoami.exe -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBhAGwAbAA='))) -Wait -NoNewWindow


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBsAG8AdQBkACAAQwByAGUAZABlAG4AdABpAGEAbABzACAAQwBoAGUAYwBrAA==')))
${__/=\_/\/==\/===\} = (ls C:\Users).Name
${_/=\/\_/\_/=\/\/\} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBhAHcAcwBcAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABnAGMAbABvAHUAZABcAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAuAGQAYgA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABnAGMAbABvAHUAZABcAGwAZQBnAGEAYwB5AF8AYwByAGUAZABlAG4AdABpAGEAbABzAA=='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABnAGMAbABvAHUAZABcAGEAYwBjAGUAcwBzAF8AdABvAGsAZQBuAHMALgBkAGIA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBhAHoAdQByAGUAXABhAGMAYwBlAHMAcwBUAG8AawBlAG4AcwAuAGoAcwBvAG4A'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBhAHoAdQByAGUAXABhAHoAdQByAGUAUAByAG8AZgBpAGwAZQAuAGoAcwBvAG4A')))) 
foreach (${/==\/==\__/=\_/\_} in ${__/=\_/\/==\/===\}) {
  ${_/=\/\_/\_/=\/\/\} | % {
    if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwA6AFwAJAB1AFwAJABfAA==')))) { Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABfACAAZgBvAHUAbgBkACEA'))) -ForegroundColor Red }
  }
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQQBQAFAAYwBtAGQAIABDAGgAZQBjAGsA')))
if (Test-Path ($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AFMAeQBzAHQAZQBtAFIAbwBvAHQAXABTAHkAcwB0AGUAbQAzADIAXABpAG4AZQB0AHMAcgB2AFwAYQBwAHAAYwBtAGQALgBlAHgAZQA='))))) {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAYQBwAHAAYwBtAGQALgBlAHgAZQA='))) -ForegroundColor Yellow
  Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AFMAeQBzAHQAZQBtAFIAbwBvAHQAXABTAHkAcwB0AGUAbQAzADIAXABpAG4AZQB0AHMAcgB2AFwAYQBwAHAAYwBtAGQALgBlAHgAZQAgAGUAeABpAHMAdABzACEA'))) -ForegroundColor Red
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATwBwAGUAbgBWAFAATgAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAEMAaABlAGMAawA=')))

${__/=\/\_/\___/=\_} = ls $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATwBwAGUAbgBWAFAATgAtAEcAVQBJAFwAYwBvAG4AZgBpAGcAcwA='))) -ErrorAction SilentlyContinue
if (${__/=\/\_/\___/=\_}) {
  Add-Type -AssemblyName System.Security
  ${__/\/\/\/==\/\/\/} = ${__/=\/\_/\___/=\_} | % { gp $_.PsPath }
  foreach (${/==\_/===\/=\_/\/} in ${__/\/\/\/==\/\/\/}) {
    ${/==\_/==\/===\__/} = ${/==\_/===\/=\_/\/}.'auth-data'
    ${_/=\/=\_/==\_/==\} = ${/==\_/===\/=\_/\/}.'entropy'
    ${_/=\/=\_/==\_/==\} = ${_/=\/=\_/==\_/==\}[0..((${_/=\/=\_/==\_/==\}.Length) - 2)]

    ${_/==\/=\/=\___/=\} = [System.Security.Cryptography.ProtectedData]::Unprotect(
      ${/==\_/==\/===\__/}, 
      ${_/=\/=\_/==\_/==\}, 
      [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
 
    Write-Host ([System.Text.Encoding]::Unicode.GetString(${_/==\/=\/=\___/=\}))
  }
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUABvAHcAZQByAFMAaABlAGwAbAAgAEgAaQBzAHQAbwByAHkAIAAoAFAAYQBzAHMAdwBvAHIAZAAgAFMAZQBhAHIAYwBoACAATwBuAGwAeQApAA==')))

Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQB8AHwAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAQwBvAG4AcwBvAGwAZQAgAEgAaQBzAHQAbwByAHkA')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQB8AHwAIABUAG8AIABzAGUAZQAgAGEAbABsACAAaABpAHMAdABvAHIAeQAsACAAcgB1AG4AIAB0AGgAaQBzACAAYwBvAG0AbQBhAG4AZAA6ACAARwBlAHQALQBDAG8AbgB0AGUAbgB0ACAAKABHAGUAdAAtAFAAUwBSAGUAYQBkAGwAaQBuAGUATwBwAHQAaQBvAG4AKQAuAEgAaQBzAHQAbwByAHkAUwBhAHYAZQBQAGEAdABoAA==')))
Write-Host $(gc (Get-PSReadLineOption).HistorySavePath | sls pa)

Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQB8AHwAIABBAHAAcABEAGEAdABhACAAUABTAFIAZQBhAGQAbABpAG4AZQAgAEMAbwBuAHMAbwBsAGUAIABIAGkAcwB0AG8AcgB5ACAA')))
Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQB8AHwAIABUAG8AIABzAGUAZQAgAGEAbABsACAAaABpAHMAdABvAHIAeQAsACAAcgB1AG4AIAB0AGgAaQBzACAAYwBvAG0AbQBhAG4AZAA6ACAARwBlAHQALQBDAG8AbgB0AGUAbgB0ACAAJABlAG4AdgA6AFUAUwBFAFIAUABSAE8ARgBJAEwARQBcAEEAcABwAEQAYQB0AGEAXABSAG8AYQBtAGkAbgBnAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAUABvAHcAZQByAFMAaABlAGwAbABcAFAAUwBSAGUAYQBkAGwAaQBuAGUAXABDAG8AbgBzAG8AbABlAEgAbwBzAHQAXwBoAGkAcwB0AG8AcgB5AC4AdAB4AHQA')))
Write-Host $(gc $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFUAUwBFAFIAUABSAE8ARgBJAEwARQBcAEEAcABwAEQAYQB0AGEAXABSAG8AYQBtAGkAbgBnAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAUABvAHcAZQByAFMAaABlAGwAbABcAFAAUwBSAGUAYQBkAGwAaQBuAGUAXABDAG8AbgBzAG8AbABlAEgAbwBzAHQAXwBoAGkAcwB0AG8AcgB5AC4AdAB4AHQA'))) | sls pa)


Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQB8AHwAIABQAG8AdwBlAHMAUgBoAGUAbABsACAAZABlAGYAYQB1AGwAdAAgAHQAcgBhAG4AcwByAGMAaQBwAHQAIABoAGkAcwB0AG8AcgB5ACAAYwBoAGUAYwBrACAA')))
if (Test-Path $env:SystemDrive\transcripts\) { "Default transcripts found at $($env:SystemDrive)\transcripts\" }



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAARQBOAFYASQBSAE8ATgBNAEUATgBUACAAVgBBAFIASQBBAEIATABFAFMAIAA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHkAYgBlACAAeQBvAHUAIABjAGEAbgAgAHQAYQBrAGUAIABhAGQAdgBhAG4AdABhAGcAZQAgAG8AZgAgAG0AbwBkAGkAZgB5AGkAbgBnAC8AYwByAGUAYQB0AGkAbgBnACAAYQAgAGIAaQBuAGEAcgB5ACAAaQBuACAAcwBvAG0AZQAgAG8AZgAgAHQAaABlACAAZgBvAGwAbABvAHcAaQBuAGcAIABsAG8AYwBhAHQAaQBvAG4AcwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFQASAAgAHYAYQByAGkAYQBiAGwAZQAgAGUAbgB0AHIAaQBlAHMAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMAIAAtACAAcABsAGEAYwBlACAAYgBpAG4AYQByAHkAIABvAHIAIABEAEwATAAgAHQAbwAgAGUAeABlAGMAdQB0AGUAIABpAG4AcwB0AGUAYQBkACAAbwBmACAAbABlAGcAaQB0AGkAbQBhAHQAZQA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAZABsAGwALQBoAGkAagBhAGMAawBpAG4AZwA='))) -ForegroundColor Yellow

ls env: | ft -Wrap


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwB0AGkAYwBrAHkAIABOAG8AdABlAHMAIABDAGgAZQBjAGsA')))
if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJABlAG4AdgA6AFUAUwBFAFIATgBBAE0ARQBcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABQAGEAYwBrAGEAZwBlAHMAXABNAGkAYwByAG8AcwBvAGYAdAAuAE0AaQBjAHIAbwBzAG8AZgB0AFMAdABpAGMAawB5AE4AbwB0AGUAcwAqAFwATABvAGMAYQBsAFMAdABhAHQAZQBcAHAAbAB1AG0ALgBzAHEAbABpAHQAZQA=')))) {
  Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGkAYwBrAHkAIABOAG8AdABlAHMAIABkAGEAdABhAGIAYQBzAGUAIABmAG8AdQBuAGQALgAgAEMAbwB1AGwAZAAgAGgAYQB2AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABpAG4AIABwAGwAYQBpAG4AIAB0AGUAeAB0ADoAIAA=')))
  Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJABlAG4AdgA6AFUAUwBFAFIATgBBAE0ARQBcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABQAGEAYwBrAGEAZwBlAHMAXABNAGkAYwByAG8AcwBvAGYAdAAuAE0AaQBjAHIAbwBzAG8AZgB0AFMAdABpAGMAawB5AE4AbwB0AGUAcwAqAFwATABvAGMAYQBsAFMAdABhAHQAZQBcAHAAbAB1AG0ALgBzAHEAbABpAHQAZQA=')))
}



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBhAGMAaABlAGQAIABDAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABDAGgAZQBjAGsA')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAdwBpAG4AZABvAHcAcwAtAHYAYQB1AGwAdAA='))) -ForegroundColor Yellow 
cmdkey.exe /list


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABEAFAAQQBQAEkAIABSAFAAQwAgAE0AYQBzAHQAZQByACAASwBlAHkAcwA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIAB0AGgAZQAgAE0AaQBtAGkAawBhAHQAegAgACcAZABwAGEAcABpADoAOgBtAGEAcwB0AGUAcgBrAGUAeQAnACAAbQBvAGQAdQBsAGUAIAB3AGkAdABoACAAYQBwAHAAcgBvAHAAcgBpAGEAdABlACAAYQByAGcAdQBtAGUAbgB0AHMAIAAoAC8AcgBwAGMAKQAgAHQAbwAgAGQAZQBjAHIAeQBwAHQA')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAZABwAGEAcABpAA=='))) -ForegroundColor Yellow

${/=\____/=\_/\/\_/} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJABlAG4AdgA6AFUAUwBFAFIATgBBAE0ARQBcAEEAcABwAEQAYQB0AGEAXABSAG8AYQBtAGkAbgBnAFwATQBpAGMAcgBvAHMAbwBmAHQAXAA=')))
${_____/\/\/=====\/} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJABlAG4AdgA6AFUAUwBFAFIATgBBAE0ARQBcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABNAGkAYwByAG8AcwBvAGYAdABcAA==')))
if ( Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAFIAbwBhAG0AaQBuAGcAXABQAHIAbwB0AGUAYwB0AFwA')))) {
  Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBvAHUAbgBkADoAIAAkAGEAcABwAGQAYQB0AGEAUgBvAGEAbQBpAG4AZwBcAFAAcgBvAHQAZQBjAHQAXAA=')))
  ls -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAFIAbwBhAG0AaQBuAGcAXABQAHIAbwB0AGUAYwB0AFwA'))) -Force | % {
    Write-Host $_.FullName
  }
}
if ( Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAEwAbwBjAGEAbABcAFAAcgBvAHQAZQBjAHQAXAA=')))) {
  Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBvAHUAbgBkADoAIAAkAGEAcABwAGQAYQB0AGEATABvAGMAYQBsAFwAUAByAG8AdABlAGMAdABcAA==')))
  ls -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAEwAbwBjAGEAbABcAFAAcgBvAHQAZQBjAHQAXAA='))) -Force | % {
    Write-Host $_.FullName
  }
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwBoAGUAYwBrAGkAbgBnACAAZgBvAHIAIABEAFAAQQBQAEkAIABDAHIAZQBkACAATQBhAHMAdABlAHIAIABLAGUAeQBzAA==')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIAB0AGgAZQAgAE0AaQBtAGkAawBhAHQAegAgACcAZABwAGEAcABpADoAOgBjAHIAZQBkACcAIABtAG8AZAB1AGwAZQAgAHcAaQB0AGgAIABhAHAAcAByAG8AcAByAGkAYQB0AGUAIAAvAG0AYQBzAHQAZQByAGsAZQB5ACAAdABvACAAZABlAGMAcgB5AHAAdAA='))) 
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBvAHUAIABjAGEAbgAgAGEAbABzAG8AIABlAHgAdAByAGEAYwB0ACAAbQBhAG4AeQAgAEQAUABBAFAASQAgAG0AYQBzAHQAZQByAGsAZQB5AHMAIABmAHIAbwBtACAAbQBlAG0AbwByAHkAIAB3AGkAdABoACAAdABoAGUAIABNAGkAbQBpAGsAYQB0AHoAIAAnAHMAZQBrAHUAcgBsAHMAYQA6ADoAZABwAGEAcABpACcAIABtAG8AZAB1AGwAZQA='))) 
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAGIAbwBvAGsALgBoAGEAYwBrAHQAcgBpAGMAawBzAC4AeAB5AHoALwB3AGkAbgBkAG8AdwBzAC0AaABhAHIAZABlAG4AaQBuAGcALwB3AGkAbgBkAG8AdwBzAC0AbABvAGMAYQBsAC0AcAByAGkAdgBpAGwAZQBnAGUALQBlAHMAYwBhAGwAYQB0AGkAbwBuACMAZABwAGEAcABpAA=='))) -ForegroundColor Yellow

if ( Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAFIAbwBhAG0AaQBuAGcAXABDAHIAZQBkAGUAbgB0AGkAYQBsAHMAXAA=')))) {
  ls -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAFIAbwBhAG0AaQBuAGcAXABDAHIAZQBkAGUAbgB0AGkAYQBsAHMAXAA='))) -Force
}
if ( Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAEwAbwBjAGEAbABcAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwBcAA==')))) {
  ls -Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABhAHAAcABkAGEAdABhAEwAbwBjAGEAbABcAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwBcAA=='))) -Force
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAQwB1AHIAcgBlAG4AdAAgAEwAbwBnAGcAZQBkACAAbwBuACAAVQBzAGUAcgBzAA==')))
try { quser }catch { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwBxAHUAcwBlAHIAJwAgAGMAbwBtAG0AYQBuAGQAIABuAG8AdAAgAG4AbwB0ACAAcAByAGUAcwBlAG4AdAAgAG8AbgAgAHMAeQBzAHQAZQBtAA=='))) } 


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBlAG0AbwB0AGUAIABTAGUAcwBzAGkAbwBuAHMA')))
try { qwinsta } catch { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwBxAHcAaQBuAHMAdABhACcAIABjAG8AbQBtAGEAbgBkACAAbgBvAHQAIABwAHIAZQBzAGUAbgB0ACAAbwBuACAAcwB5AHMAdABlAG0A'))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAASwBlAHIAYgBlAHIAbwBzACAAdABpAGMAawBlAHQAcwAgACgAZABvAGUAcwAgAHIAZQBxAHUAaQByAGUAIABhAGQAbQBpAG4AIAB0AG8AIABpAG4AdABlAHIAYQBjAHQAKQA=')))
try { klist } catch { Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvACAAYQBjAHQAaQB2AGUAIABzAGUAcwBzAGkAbwBuAHMA'))) }


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUAByAGkAbgB0AGkAbgBnACAAQwBsAGkAcABCAG8AYQByAGQAIAAoAGkAZgAgAGEAbgB5ACkA')))
_/=\_/\_/\/\/====\


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAVQBuAGEAdAB0AGUAbgBkAGUAZAAgAEYAaQBsAGUAcwAgAEMAaABlAGMAawA=')))
@($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHAAcgBlAHAAXABzAHkAcwBwAHIAZQBwAC4AeABtAGwA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHAAcgBlAHAAXABzAHkAcwBwAHIAZQBwAC4AaQBuAGYA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAHMAeQBzAHAAcgBlAHAALgBpAG4AZgA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFAAYQBuAHQAaABlAHIAXABVAG4AYQB0AHQAZQBuAGQAZQBkAC4AeABtAGwA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFAAYQBuAHQAaABlAHIAXABVAG4AYQB0AHQAZQBuAGQALgB4AG0AbAA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFAAYQBuAHQAaABlAHIAXABVAG4AYQB0AHQAZQBuAGQAXABVAG4AYQB0AHQAZQBuAGQALgB4AG0AbAA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFAAYQBuAHQAaABlAHIAXABVAG4AYQB0AHQAZQBuAGQAXABVAG4AYQB0AHQAZQBuAGQAZQBkAC4AeABtAGwA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAFMAeQBzAHAAcgBlAHAAXAB1AG4AYQB0AHQAZQBuAGQALgB4AG0AbAA='))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAFMAeQBzAHAAcgBlAHAAXAB1AG4AYQB0AHQAZQBuAGQAZQBkAC4AeABtAGwA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAdQBuAGEAdAB0AGUAbgBkAC4AdAB4AHQA'))),
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAdQBuAGEAdAB0AGUAbgBkAC4AaQBuAGYA')))) | % {
  if (Test-Path $_) {
    Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABfACAAZgBvAHUAbgBkAC4A')))
  }
}



Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUwBBAE0AIAAvACAAUwBZAFMAVABFAE0AIABCAGEAYwBrAHUAcAAgAEMAaABlAGMAawBzAA==')))

@(
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AHcAaQBuAGQAaQByAFwAcgBlAHAAYQBpAHIAXABTAEEATQA='))),
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AHcAaQBuAGQAaQByAFwAUwB5AHMAdABlAG0AMwAyAFwAYwBvAG4AZgBpAGcAXABSAGUAZwBCAGEAYwBrAFwAUwBBAE0A'))),
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AHcAaQBuAGQAaQByAFwAUwB5AHMAdABlAG0AMwAyAFwAYwBvAG4AZgBpAGcAXABTAEEATQA='))),
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AHcAaQBuAGQAaQByAFwAcgBlAHAAYQBpAHIAXABzAHkAcwB0AGUAbQA='))),
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AHcAaQBuAGQAaQByAFwAUwB5AHMAdABlAG0AMwAyAFwAYwBvAG4AZgBpAGcAXABTAFkAUwBUAEUATQA='))),
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABFAG4AdgA6AHcAaQBuAGQAaQByAFwAUwB5AHMAdABlAG0AMwAyAFwAYwBvAG4AZgBpAGcAXABSAGUAZwBCAGEAYwBrAFwAcwB5AHMAdABlAG0A')))) | % {
  if (Test-Path $_ -ErrorAction SilentlyContinue) {
    Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABfACAARgBvAHUAbgBkACEA'))) -ForegroundColor red
  }
}


Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAARwByAG8AdQBwACAAUABvAGwAaQBjAHkAIABQAGEAcwBzAHcAbwByAGQAIABDAGgAZQBjAGsA')))

${/===\/\_/=\/\/=\_} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAHMALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAC4AeABtAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAdABhAHMAawBzAC4AeABtAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAG8AdQByAGMAZQBzAC4AeABtAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAC4AeABtAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAHMALgB4AG0AbAA='))))
if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFMAeQBzAHQAZQBtAEQAcgBpAHYAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwARwByAG8AdQBwACAAUABvAGwAaQBjAHkAXABoAGkAcwB0AG8AcgB5AA==')))) {
  ls -Recurse -Force $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFMAeQBzAHQAZQBtAEQAcgBpAHYAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwARwByAG8AdQBwACAAUABvAGwAaQBjAHkAXABoAGkAcwB0AG8AcgB5AA=='))) -Include @/===\/\_/=\/\/=\_
}

if (Test-Path $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFMAeQBzAHQAZQBtAEQAcgBpAHYAZQBcAEQAbwBjAHUAbQBlAG4AdABzACAAYQBuAGQAIABTAGUAdAB0AGkAbgBnAHMAXABBAGwAbAAgAFUAcwBlAHIAcwBcAEEAcABwAGwAaQBjAGEAdABpAG8AbgAgAEQAYQB0AGEAXABNAGkAYwByAG8AcwBvAGYAdABcAEcAcgBvAHUAcAAgAFAAbwBsAGkAYwB5AFwAaABpAHMAdABvAHIAeQA='))) ) {
  ls -Recurse -Force $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABlAG4AdgA6AFMAeQBzAHQAZQBtAEQAcgBpAHYAZQBcAEQAbwBjAHUAbQBlAG4AdABzACAAYQBuAGQAIABTAGUAdAB0AGkAbgBnAHMAXABBAGwAbAAgAFUAcwBlAHIAcwBcAEEAcABwAGwAaQBjAGEAdABpAG8AbgAgAEQAYQB0AGEAXABNAGkAYwByAG8AcwBvAGYAdABcAEcAcgBvAHUAcAAgAFAAbwBsAGkAYwB5AFwAaABpAHMAdABvAHIAeQA=')))
}

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBlAGMAeQBjAGwAZQAgAEIAaQBuACAAVABJAFAAOgA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBmACAAYwByAGUAZABlAG4AdABpAGEAbABzACAAYQByAGUAIABmAG8AdQBuAGQAIABpAG4AIAB0AGgAZQAgAHIAZQBjAHkAYwBsAGUAIABiAGkAbgAsACAAdABvAG8AbAAgAGYAcgBvAG0AIABuAGkAcgBzAG8AZgB0ACAAbQBhAHkAIABhAHMAcwBpAHMAdAA6ACAAaAB0AHQAcAA6AC8ALwB3AHcAdwAuAG4AaQByAHMAbwBmAHQALgBuAGUAdAAvAHAAYQBzAHMAdwBvAHIAZABfAHIAZQBjAG8AdgBlAHIAeQBfAHQAbwBvAGwAcwAuAGgAdABtAGwA'))) -ForegroundColor Yellow

Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUgBlAGcAaQBzAHQAcgB5ACAAUABhAHMAcwB3AG8AcgBkACAAQwBoAGUAYwBrAA==')))

Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAGkAbgBnACAAbwB2AGUAcgAgADIAMAAwACAAZABpAGYAZgBlAHIAZQBuAHQAIABwAGEAcwBzAHcAbwByAGQAIAByAGUAZwBlAHgAIAB0AHkAcABlAHMALgA=')))
Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAHcAaQBsAGwAIAB0AGEAawBlACAAcwBvAG0AZQAgAHQAaQBtAGUALgAgAFcAbwBuACcAdAAgAHkAbwB1ACAAaABhAHYAZQAgAGEAIABwAGUAcABzAGkAPwA=')))
${/=\/======\_/\__/} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBcAEgASwBFAFkAXwBDAFUAUgBSAEUATgBUAF8AVQBTAEUAUgBcAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgBcAEgASwBFAFkAXwBMAE8AQwBBAEwAXwBNAEEAQwBIAEkATgBFAFwA'))))

foreach (${_/\/=\__/=\/=\__/} in ${/=\/======\_/\__/}) {
(ls -Path ${_/\/=\__/=\/=\__/} -Recurse -Force -ErrorAction SilentlyContinue) | % {
    ${/====\/===\/==\_/} = $_.property
    ${_/====\_/\/=\_/==} = $_.Name
    ${/====\/===\/==\_/} | % {
      ${_/====\___/\_/\_/} = $_
      ${/==\/\__/====\/\/}.keys | % {
        ${_/\/=====\/\___/=} = ${/==\/\__/====\/\/}[$_]
        if (${_/====\___/\_/\_/} | ? { $_ -like ${_/\/=====\/\___/=} }) {
          Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAcwBpAGIAbABlACAAUABhAHMAcwB3AG8AcgBkACAARgBvAHUAbgBkADoAIAAkAE4AYQBtAGUAXAAkAFAAcgBvAHAA')))
          Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHkAOgAgACQAXwA='))) -ForegroundColor Red
        }
        ${_/====\___/\_/\_/} | % {   
          ${/==\/\__/\_/\/=\/} = (gp $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGcAaQBzAHQAcgB5ADoAOgAkAE4AYQBtAGUA')))).$_
          if (${/==\/\__/\_/\/=\/} | ? { $_ -like ${_/\/=====\/\___/=} }) {
            Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAcwBpAGIAbABlACAAUABhAHMAcwB3AG8AcgBkACAARgBvAHUAbgBkADoAIAAkAG4AYQBtAGUAXAAkAF8AIAAkAHAAcgBvAHAAVgBhAGwAdQBlAA==')))
          }
        }
      }
    }
  }
  if ($TimeStamp) { __/==\_____/===\/\ }
  Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AaQBzAGgAZQBkACAAJAByAA==')))
}

Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAIABQAGEAcwBzAHcAbwByAGQAIABDAGgAZQBjAGsAIABpAG4AIABGAGkAbABlAHMA')))

${_/\/\_/===\_/==\_} = gdr | ? { $_.Root -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgA6AFwA'))) }
${_/\/\/===\/==\/==} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbQBsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHQAeAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAbwBuAGYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAbwBuAGYAaQBnAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAZgBnAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGkAbgBpAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgB5ACoAbQBsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGwAbwBnAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGIAYQBrAA=='))))
Write-Host ""
if ($TimeStamp) { __/==\_____/===\/\ }
Write-Host -ForegroundColor Blue $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAAUABhAHMAcwB3AG8AcgBkACAAQwBoAGUAYwBrAC4AIABTAHQAYQByAHQAaQBuAGcAIABhAHQAIAByAG8AbwB0ACAAbwBmACAAZQBhAGMAaAAgAGQAcgBpAHYAZQAuACAAVABoAGkAcwAgAHcAaQBsAGwAIAB0AGEAawBlACAAcwBvAG0AZQAgAHQAaQBtAGUALgAgAEwAaQBrAGUALAAgAGcAcgBhAGIAIABhACAAYwBvAGYAZgBlAGUAIABvAHIAIAB0AGUAYQAuAA==')))
Write-Host -ForegroundColor Blue $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PQA9AD0APQA9AD0APQA9AD0AfAB8ACAATABvAG8AawBpAG4AZwAgAHQAaAByAG8AdQBnAGgAIABlAGEAYwBoACAAZAByAGkAdgBlACwAIABzAGUAYQByAGMAaABpAG4AZwAgAGYAbwByACAAJABmAGkAbABlAEUAeAB0AGUAbgBzAGkAbwBuAHMA')))

${_/\/\_/===\_/==\_}.Root | % {
  ${__/\/\/===\/=\/\_} = $_
  ls ${__/\/\/===\/=\/\_} -Recurse -Include ${_/\/\/===\/==\/==} -ErrorAction SilentlyContinue | % {
    ${/==\/=\/====\_/==} = $_
    if (${/==\/=\/====\_/==} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAGkAdABlAEwAaQBzAHQALgB4AG0AbAA=')))) {
      Write-Host "Possible MCaffee Site List Found: $($_.FullName)"
      Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgB1AHMAdAAgAGcAbwBpAG4AZwAgAHQAbwAgAGwAZQBhAHYAZQAgAHQAaABpAHMAIABoAGUAcgBlADoAIABoAHQAdABwAHMAOgAvAC8AZwBpAHQAaAB1AGIALgBjAG8AbQAvAGYAdQBuAG8AdgBlAHIAaQBwAC8AbQBjAGEAZgBlAGUALQBzAGkAdABlAGwAaQBzAHQALQBwAHcAZAAtAGQAZQBjAHIAeQBwAHQAaQBvAG4A'))) -ForegroundColor Yellow
    }
    ${/==\/\__/====\/\/}.keys | % {
      ${________/===\/\_/} = gc ${/==\/=\/====\_/==}.FullName -ErrorAction SilentlyContinue | sls ${/==\/\__/====\/\/}[$_]
      if (${________/===\/\_/}) {
        Write-Host $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAcwBpAGIAbABlACAAUABhAHMAcwB3AG8AcgBkACAAZgBvAHUAbgBkADoAIAAkAF8A'))) -ForegroundColor Yellow
        Write-Host ${/==\/=\/====\_/==}.FullName
        Write-Host ${________/===\/\_/} -ForegroundColor Red
      }
    }
  }
}