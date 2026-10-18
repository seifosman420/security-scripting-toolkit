# Export-PSHistory

Collects PowerShell (PSReadLine) command history from **every user profile on a
host** into **one searchable file** (JSONL or CSV), with provenance and an
integrity hash.

**Platform:** Windows PowerShell 5.1, PowerShell 7+ (Windows, Linux, macOS)
**ATT&CK context:** T1059.001 (PowerShell) hunting and triage; T1070.003
(Clear Command History) when history is missing or truncated
**Status:** experimental · **Tests:** `tests/Test-ExportPSHistory.ps1`

> Use only on systems you are authorized to investigate. History files can
> contain secrets typed on the command line. Treat the output as sensitive.

## Why

During triage, "what did PowerShell run on this box, and who ran it?" is
scattered across one history file per user, per host application. This script
flattens all of it into one record-per-command file you can grep, load into a
SIEM, query with jq/DuckDB, or filter in PowerShell.

## Usage

```powershell
# Everything on this host (run elevated to read other users' profiles)
.\Export-PSHistory.ps1

# Offline image mounted at E:\, with triage hints, custom name
.\Export-PSHistory.ps1 -UsersRoot E:\Users -HostLabel WKS-0421 -AddTags -OutputPath .\wks0421.jsonl

# CSV for Excel / spreadsheet people
.\Export-PSHistory.ps1 -Format CSV -OutputPath C:\IR\history.csv

# A history file saved to a non-default location
.\Export-PSHistory.ps1 -ExtraHistoryPath D:\custom\my_history.txt
```

| Parameter | Purpose |
|---|---|
| `-OutputPath` | Output file (default `pshistory_<host>_<UTC time>.jsonl`) |
| `-Format` | `JSONL` (default) or `CSV` |
| `-UsersRoot` | Folder(s) containing profile folders (e.g. a mounted image) |
| `-ProfilePath` | Specific profile folder(s) |
| `-ExtraHistoryPath` | Explicit history file(s), e.g. custom `HistorySavePath` |
| `-HostLabel` | Hostname to record (for images or remote collection) |
| `-SkipServiceProfiles` | Skip SYSTEM / LOCAL SERVICE / NETWORK SERVICE (Windows default mode) |
| `-AddTags` | Add heuristic triage hints (see below) |
| `-Force` | Overwrite an existing output file |

Default scan locations when no `-UsersRoot`/`-ProfilePath` is given:
Windows: `C:\Users\*` plus the SYSTEM, LOCAL SERVICE and NETWORK SERVICE
profiles. Linux/macOS: `/home/*`, `/Users/*`, `/root`.

History files found per profile (any `*_history.txt`, so VS Code and other
hosts are included):

- `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\`
- `.local/share/powershell/PSReadLine/`

## Output

One record per command. Multi-line commands are one record with embedded newlines.

| Field | Meaning |
|---|---|
| `collected_at_utc` | When the collection ran |
| `hostname` | Machine name, or `-HostLabel` |
| `user` | Profile folder name (`SYSTEM`, etc. for service profiles; `(unknown)` for `-ExtraHistoryPath`) |
| `profile_path` | Profile directory |
| `history_file` / `history_host` | Source file and which host app wrote it (`ConsoleHost`, `Visual Studio Code Host`, ...) |
| `file_last_write_utc` | Last write time of the history file |
| `file_sha256` | SHA-256 of the history file as read |
| `command_index` | Position in the file (higher = more recent) |
| `line_number` / `line_count` | Where the command starts in the file and how many lines it spans |
| `command` | The command text |
| `command_length` | Characters |
| `tags` | Only with `-AddTags`; array in JSONL, `;`-joined in CSV |

A `<output>.sha256` file (sha256sum format) is written next to the output, and
a summary object (`OutputPath`, `Sha256`, `Users`, `HistoryFiles`, `Commands`,
`Errors`) is returned. Errors on individual profiles or files are reported
and collection continues.

See [SEARCHING.md](SEARCHING.md) for jq, DuckDB, grep and PowerShell recipes, and
[examples/sample_output.jsonl](examples/sample_output.jsonl) for synthetic output.

## Tags

`-AddTags` adds hints from simple regexes: `encoded_command`, `base64_handling`,
`download_cradle`, `invoke_expression`, `execution_policy_bypass`,
`hidden_window`, `defense_tamper`, `credential_access`, `persistence`,
`remote_execution`. **They are triage aids, not verdicts.** Plenty of benign
admin work matches (`Invoke-Command`, `Set-ExecutionPolicy`), and a determined
attacker will not match. Rules live in `Get-PSHistoryTag`.

## Design notes

- **Read-only.** Files are opened for read with shared read/write/delete, so
  live files can be read. A test asserts source files are unchanged (hash and mtime).
- **Never overwrites** the output unless `-Force`.
- **Integrity:** per-file hashes in every record, plus a sidecar hash of the output.
- **Compatibility:** no PowerShell 7-only syntax; output is UTF-8 without BOM.
- **No network calls, no dependencies.**
- **Testable:** dot-sourcing the script loads the functions without running main.

## Limitations (read before relying on this)

- **No per-command timestamps.** PSReadLine does not record them. You get
  order (`command_index`) and the file's last-write time, nothing more. For
  timing, correlate with script block logging (event 4104), Sysmon, or EDR.
- **Only interactive PSReadLine sessions.** Not recorded: `-Command`/`-File`
  runs, most remote sessions, PowerShell ISE, and anything run by tools that
  bypass PSReadLine.
- **Attackers and users can avoid or erase it.** History can be disabled
  (`Set-PSReadLineOption -HistorySaveStyle SaveNothing`), the file deleted, or
  edited. Recent PSReadLine versions also skip saving lines that match
  sensitive keywords (password, token, secret...), so absence is not proof of absence.
- **Multi-line reassembly is heuristic.** It relies on PSReadLine's trailing-backtick
  format. A command that itself ends a line with a backtick can be misjoined.
- **Custom or redirected paths are not discovered** (custom `HistorySavePath`,
  `XDG_DATA_HOME` on Linux). Use `-ExtraHistoryPath`.
- **Windows default scan needs elevation** to read other users and service
  profiles. The script warns when not elevated.
- **Windows PowerShell 5.1 escapes** `<`, `>`, `&` and `'` as `\uXXXX` in JSON.
  Valid JSON, but raw `grep` for those characters misses; use jq or PowerShell.

## Testing

```powershell
pwsh ./tests/Test-ExportPSHistory.ps1        # or powershell.exe on Windows
```

38 assertions, no dependencies, exit code 1 on failure. Fixtures are generated
at test time (`tests/New-FakePSHistoryProfiles.ps1`): both OS path layouts,
CRLF and LF, UTF-8 BOM, blank lines, non-ASCII, a profile with no history,
multi-line commands.

Verified on PowerShell 7.4 on Linux. CI runs Windows PowerShell 5.1 and
PowerShell 7 on Windows and Ubuntu (see `.github/workflows/ci.yml`).

## Ideas / roadmap

- Optional `-Since` filter on file last-write time
- Collect `Start-Transcript` output folders
- Parse event 4104 script block logs into the same schema
- Signed, timestamped collection manifest
