#Requires -Version 5.1
<#
.SYNOPSIS
    Collects PowerShell (PSReadLine) history files from every user profile on a
    host into one searchable file (JSONL or CSV).

.DESCRIPTION
    Finds PSReadLine history files (ConsoleHost_history.txt, the VS Code host
    equivalent, etc.) for all user profiles, parses them into one record per
    command, and writes a single output file with one command per line (JSONL)
    or per row (CSV). Each record carries host, user, source file, file hash,
    line position and the command text, so results can be grepped, loaded into
    jq / DuckDB / a SIEM, or filtered with PowerShell.

    The script is READ-ONLY with respect to the history files: they are opened
    with read access and shared read/write/delete so live files can be read.

    Reading other users' profiles normally requires an elevated session.

    Limitations (see README): PSReadLine history has no per-command timestamps,
    only the file's last-write time. Multi-line commands are reassembled
    heuristically from PSReadLine's backtick continuation format.

.PARAMETER OutputPath
    Output file. Default: .\pshistory_<host>_<UTC timestamp>.<jsonl|csv>

.PARAMETER Format
    JSONL (default, one JSON object per line) or CSV.

.PARAMETER UsersRoot
    One or more directories that contain user profile folders (for example an
    offline image mounted at E:\Users). If neither UsersRoot nor ProfilePath is
    supplied, platform defaults are used (C:\Users, plus the SYSTEM / LOCAL
    SERVICE / NETWORK SERVICE profiles on Windows; /home, /Users and /root on
    Linux and macOS).

.PARAMETER ProfilePath
    One or more individual profile directories to scan.

.PARAMETER ExtraHistoryPath
    Explicit history files to include, e.g. when HistorySavePath was customized.

.PARAMETER HostLabel
    Hostname to record instead of the local machine name. Useful when scanning
    a mounted image or collecting remotely.

.PARAMETER SkipServiceProfiles
    Do not scan the SYSTEM, LOCAL SERVICE and NETWORK SERVICE profiles
    (default mode on Windows only).

.PARAMETER AddTags
    Add a "tags" field with heuristic hints (encoded_command, download_cradle,
    invoke_expression, ...). Hints are for triage, not verdicts.

.PARAMETER Force
    Overwrite OutputPath if it already exists.

.EXAMPLE
    .\Export-PSHistory.ps1
    Collect from all profiles on this host into ./pshistory_<host>_<time>.jsonl

.EXAMPLE
    .\Export-PSHistory.ps1 -UsersRoot E:\Users -HostLabel WKS-0421 -AddTags -OutputPath .\wks0421.jsonl

.EXAMPLE
    .\Export-PSHistory.ps1 -Format CSV -OutputPath C:\IR\history.csv -Force

.OUTPUTS
    A summary object (OutputPath, Sha256, Host, Users, HistoryFiles, Commands,
    Errors). A <OutputPath>.sha256 file is written next to the output.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [ValidateSet('JSONL', 'CSV')]
    [string]$Format = 'JSONL',

    [string[]]$UsersRoot,

    [string[]]$ProfilePath,

    [string[]]$ExtraHistoryPath,

    [string]$HostLabel,

    [switch]$SkipServiceProfiles,

    [switch]$AddTags,

    [switch]$Force
)

function Test-IsWindowsPlatform {
    [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-IsElevated {
    if (Test-IsWindowsPlatform) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    return ([System.Environment]::UserName -eq 'root')
}

function Get-PSHistoryTag {
    <# Heuristic triage hints. Many hits are benign; many attacks will not match. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Command)

    $rules = [ordered]@{
        encoded_command         = '(?<!\w)-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}'
        base64_handling         = 'frombase64string|tobase64string'
        download_cradle         = 'downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer'
        invoke_expression       = '\binvoke-expression\b|(?<![\w-])iex(?![\w-])'
        execution_policy_bypass = '-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)|set-executionpolicy\s+(?:bypass|unrestricted)'
        hidden_window           = '-w(?:indowstyle)?\s+hidden'
        defense_tamper          = 'amsiutils|amsiinitfailed|set-mppreference.*disable|disablerealtimemonitoring|scriptblocklogging'
        credential_access       = 'mimikatz|sekurlsa|lsass|ntds\.dit|comsvcs\.dll'
        persistence             = 'schtasks(?:\.exe)?\s+/create|register-scheduledtask|new-scheduledtask|currentversion\\run|sc(?:\.exe)?\s+create'
        remote_execution        = 'invoke-command|enter-pssession|new-pssession|invoke-wmimethod|invoke-cimmethod|psexec'
    }

    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($name in $rules.Keys) {
        if ([regex]::IsMatch($Command, $rules[$name], [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $hits.Add($name)
        }
    }
    $hits.ToArray()
}

function ConvertFrom-PSHistoryLine {
    <#
    Turns raw history-file lines into commands. PSReadLine stores a multi-line
    command as several lines where every line except the last ends with a
    backtick. Blank lines between commands are skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Line
    )

    $all = @($Line)
    $parts = New-Object System.Collections.Generic.List[string]
    $startLine = 0

    for ($i = 0; $i -lt $all.Count; $i++) {
        $current = [string]$all[$i]

        if ($parts.Count -eq 0) {
            if ([string]::IsNullOrWhiteSpace($current)) { continue }
            $startLine = $i + 1
        }

        $isLast = ($i -eq $all.Count - 1)
        if ($current.EndsWith('`') -and -not $isLast) {
            $parts.Add($current.Substring(0, $current.Length - 1))
            continue
        }

        $parts.Add($current)
        [pscustomobject]@{
            LineNumber = $startLine
            LineCount  = $parts.Count
            Command    = ($parts -join "`n")
        }
        $parts.Clear()
    }
}

function Read-FileBytesShared {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
    try {
        $memory = New-Object System.IO.MemoryStream
        $stream.CopyTo($memory)
        , $memory.ToArray()
    }
    finally {
        $stream.Dispose()
    }
}

function Read-PSHistoryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$User,
        [string]$ProfilePath = '',
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$CollectedAtUtc,
        [switch]$AddTags
    )

    $item = Get-Item -LiteralPath $Path -Force
    $bytes = Read-FileBytesShared -Path $item.FullName

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fileHash = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }

    $reader = [System.IO.StreamReader]::new([System.IO.MemoryStream]::new($bytes), [System.Text.UTF8Encoding]::new($false), $true)
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }

    $commands = @(ConvertFrom-PSHistoryLine -Line ([regex]::Split($text, '\r?\n')))
    $historyHost = $item.Name -replace '_history\.txt$', ''
    $lastWrite = $item.LastWriteTimeUtc.ToString('o')

    $index = 0
    foreach ($c in $commands) {
        $index++
        $record = [ordered]@{
            collected_at_utc    = $CollectedAtUtc
            hostname            = $HostName
            user                = $User
            profile_path        = $ProfilePath
            history_file        = $item.FullName
            history_host        = $historyHost
            file_last_write_utc = $lastWrite
            file_sha256         = $fileHash
            command_index       = $index
            line_number         = $c.LineNumber
            line_count          = $c.LineCount
            command             = $c.Command
            command_length      = $c.Command.Length
        }
        if ($AddTags) {
            $record['tags'] = [string[]]@(Get-PSHistoryTag -Command $c.Command)
        }
        $record
    }
}

function Get-PSHistoryProfile {
    [CmdletBinding()]
    param(
        [string[]]$UsersRoot,
        [string[]]$ProfilePath,
        [switch]$SkipServiceProfiles,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$ErrorList
    )

    $found = New-Object System.Collections.Generic.List[object]
    $explicit = ($UsersRoot -and $UsersRoot.Count -gt 0) -or ($ProfilePath -and $ProfilePath.Count -gt 0)
    $roots = @()
    $profiles = @()
    $labelled = @()

    if ($explicit) {
        $roots = @($UsersRoot | Where-Object { $_ })
        $profiles = @($ProfilePath | Where-Object { $_ })
    }
    elseif (Test-IsWindowsPlatform) {
        $drive = [System.Environment]::GetEnvironmentVariable('SystemDrive')
        if (-not $drive) { $drive = 'C:' }
        $roots = @((Join-Path -Path $drive -ChildPath 'Users'))
        if (-not $SkipServiceProfiles) {
            $sysRoot = [System.Environment]::GetEnvironmentVariable('SystemRoot')
            if (-not $sysRoot) { $sysRoot = (Join-Path -Path $drive -ChildPath 'Windows') }
            $labelled = @(
                @{ User = 'SYSTEM'; Path = [System.IO.Path]::Combine($sysRoot, 'System32', 'config', 'systemprofile') },
                @{ User = 'SYSTEM (x86)'; Path = [System.IO.Path]::Combine($sysRoot, 'SysWOW64', 'config', 'systemprofile') },
                @{ User = 'LOCAL SERVICE'; Path = [System.IO.Path]::Combine($sysRoot, 'ServiceProfiles', 'LocalService') },
                @{ User = 'NETWORK SERVICE'; Path = [System.IO.Path]::Combine($sysRoot, 'ServiceProfiles', 'NetworkService') }
            )
        }
    }
    else {
        $roots = @('/home', '/Users')
        $profiles = @('/root')
    }

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        try {
            $children = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop)
        }
        catch {
            $ErrorList.Add("Cannot enumerate '$root': $($_.Exception.Message)")
            continue
        }
        foreach ($dir in $children) {
            # Skip junctions/symlinks such as "All Users" to avoid duplicates.
            if ($dir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
            $found.Add([pscustomobject]@{ User = $dir.Name; Path = $dir.FullName })
        }
    }

    foreach ($p in $profiles) {
        if (-not (Test-Path -LiteralPath $p -PathType Container)) {
            if ($explicit) { $ErrorList.Add("Profile path not found: '$p'") }
            continue
        }
        $found.Add([pscustomobject]@{ User = (Split-Path -Path $p -Leaf); Path = (Get-Item -LiteralPath $p -Force).FullName })
    }

    foreach ($entry in $labelled) {
        if (Test-Path -LiteralPath $entry.Path -PathType Container) {
            $found.Add([pscustomobject]@{ User = $entry.User; Path = $entry.Path })
        }
    }

    $found.ToArray()
}

function Get-PSHistoryFileCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProfileDir,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$ErrorList
    )

    # Windows (Windows PowerShell 5.1 and PowerShell 7) and Linux/macOS (PowerShell 7).
    $relative = @(
        [System.IO.Path]::Combine('AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine'),
        [System.IO.Path]::Combine('.local', 'share', 'powershell', 'PSReadLine')
    )

    foreach ($rel in $relative) {
        $dir = [System.IO.Path]::Combine($ProfileDir, $rel)
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        try {
            Get-ChildItem -LiteralPath $dir -Filter '*_history.txt' -File -Force -ErrorAction Stop
        }
        catch {
            $ErrorList.Add("Cannot enumerate '$dir': $($_.Exception.Message)")
        }
    }
}

# Main. Skipped when the file is dot-sourced (so the functions can be unit tested).
if ($MyInvocation.InvocationName -ne '.') {
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'

    $errors = New-Object System.Collections.Generic.List[string]
    $collectedAt = [System.DateTime]::UtcNow
    $collectedAtText = $collectedAt.ToString('o')

    $hostName = if ($HostLabel) { $HostLabel } else { [System.Environment]::MachineName }
    $safeHost = $hostName -replace '[^\w.-]', '_'
    $extension = if ($Format -eq 'CSV') { 'csv' } else { 'jsonl' }

    if (-not $OutputPath) {
        $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath ('pshistory_{0}_{1}.{2}' -f $safeHost, $collectedAt.ToString('yyyyMMddTHHmmssZ'), $extension)
    }
    $OutputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutputPath)

    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
        throw "Output file already exists: $OutputPath (use -Force to overwrite)"
    }
    $outputDir = Split-Path -Path $OutputPath -Parent
    if ($outputDir -and -not (Test-Path -LiteralPath $outputDir -PathType Container)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    if (-not (Test-IsElevated)) {
        Write-Warning 'Not running elevated: other users'' profiles may be unreadable and will be missing from the output.'
    }

    # Discover history files, de-duplicated by full path.
    $comparer = if (Test-IsWindowsPlatform) { [System.StringComparer]::OrdinalIgnoreCase } else { [System.StringComparer]::Ordinal }
    $seen = [System.Collections.Generic.HashSet[string]]::new($comparer)
    $files = New-Object System.Collections.Generic.List[object]

    $profileParams = @{ ErrorList = $errors }
    if ($UsersRoot) { $profileParams['UsersRoot'] = $UsersRoot }
    if ($ProfilePath) { $profileParams['ProfilePath'] = $ProfilePath }
    if ($SkipServiceProfiles) { $profileParams['SkipServiceProfiles'] = $true }

    foreach ($p in @(Get-PSHistoryProfile @profileParams)) {
        foreach ($f in @(Get-PSHistoryFileCandidate -ProfileDir $p.Path -ErrorList $errors)) {
            if ($seen.Add($f.FullName)) {
                $files.Add([pscustomobject]@{ User = $p.User; ProfilePath = $p.Path; Path = $f.FullName })
            }
        }
    }

    foreach ($extra in @($ExtraHistoryPath | Where-Object { $_ })) {
        $resolved = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($extra)
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            $errors.Add("Extra history file not found: '$extra'")
            continue
        }
        if ($seen.Add($resolved)) {
            $files.Add([pscustomobject]@{ User = '(unknown)'; ProfilePath = ''; Path = $resolved })
        }
    }

    # Read, parse, write.
    $writer = New-Object System.IO.StreamWriter($OutputPath, $false, (New-Object System.Text.UTF8Encoding($false)))
    $writer.NewLine = "`n"
    $commandCount = 0
    $filesRead = 0
    $users = New-Object System.Collections.Generic.HashSet[string]
    $csvRows = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($file in $files) {
            try {
                $records = @(Read-PSHistoryFile -Path $file.Path -User $file.User -ProfilePath $file.ProfilePath `
                        -HostName $hostName -CollectedAtUtc $collectedAtText -AddTags:$AddTags)
            }
            catch {
                $errors.Add("Cannot read '$($file.Path)': $($_.Exception.Message)")
                continue
            }

            $filesRead++
            if ($records.Count -gt 0) { [void]$users.Add($file.User) }

            foreach ($record in $records) {
                $commandCount++
                if ($Format -eq 'JSONL') {
                    $writer.WriteLine((ConvertTo-Json -InputObject $record -Compress -Depth 4))
                }
                else {
                    $row = [ordered]@{}
                    foreach ($key in $record.Keys) {
                        $row[$key] = if ($key -eq 'tags') { ($record[$key] -join ';') } else { $record[$key] }
                    }
                    $csvRows.Add([pscustomobject]$row)
                }
            }
        }

        if ($Format -eq 'CSV' -and $csvRows.Count -gt 0) {
            foreach ($line in @($csvRows | ConvertTo-Csv -NoTypeInformation)) {
                $writer.WriteLine($line)
            }
        }
    }
    finally {
        $writer.Dispose()
    }

    # Integrity sidecar in `sha256sum` format.
    $outputHash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sidecar = '{0}  {1}{2}' -f $outputHash, (Split-Path -Path $OutputPath -Leaf), "`n"
    [System.IO.File]::WriteAllText("$OutputPath.sha256", $sidecar, (New-Object System.Text.UTF8Encoding($false)))

    foreach ($e in $errors) { Write-Warning $e }

    [pscustomobject]@{
        OutputPath   = $OutputPath
        Sha256       = $outputHash
        Host         = $hostName
        Format       = $Format
        Users        = @($users | Sort-Object)
        HistoryFiles = $filesRead
        Commands     = $commandCount
        Errors       = $errors.ToArray()
    }
}
