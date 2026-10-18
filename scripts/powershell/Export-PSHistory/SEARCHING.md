# Searching the output

Examples below were run against `examples/sample_output.jsonl`
(synthetic data, fields as in the README). Replace `$F` with your file.

```bash
F=examples/sample_output.jsonl
```

## jq (JSONL)

```bash
# Everything tagged as an encoded command (collect with -AddTags)
jq -c 'select(.tags | index("encoded_command")) | {user, command}' $F

# Case-insensitive regex across all commands
jq -r 'select(.command | test("downloadstring|invoke-webrequest"; "i")) | [.user, .history_host, .command] | @tsv' $F

# Commands per user
jq -s 'group_by(.user) | map({user: .[0].user, commands: length})' -c $F

# Which users ran anything tagged, and with what tags
jq -r 'select(.tags | length > 0) | "\(.user)\t\(.tags | join(","))"' $F
```

Note: `@tsv` escapes backslashes (`C:\Temp` prints as `C:\\Temp`). Use
`-r` with plain string interpolation if you need raw text.

## DuckDB (SQL over the JSONL)

```sql
-- python: duckdb.sql("...")   or the duckdb CLI
SELECT "user", count(*) AS commands
FROM read_json_auto('examples/sample_output.jsonl')
GROUP BY 1 ORDER BY 2 DESC;

SELECT "user", command
FROM read_json_auto('examples/sample_output.jsonl')
WHERE regexp_matches(command, 'downloadstring', 'i');

SELECT "user", command_index
FROM read_json_auto('examples/sample_output.jsonl')
WHERE list_contains(tags, 'encoded_command');
```

## grep (quick and dirty)

```bash
grep -i downloadstring $F
```

Each record is one line, so grep returns whole records. Caveat: on Windows
PowerShell 5.1 output, `<`, `>`, `&` and `'` appear as `\uXXXX` escapes.

## PowerShell

```powershell
$h = Get-Content .\out.jsonl | ConvertFrom-Json

$h | Where-Object command -match 'downloadstring' | Select-Object user, history_host, command
$h | Where-Object { $_.tags -contains 'remote_execution' } | ForEach-Object command
$h | Group-Object user | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count }
```

## Splunk / SIEM

JSONL ingests directly (one event per line; set `sourcetype=_json`).
There is no per-command timestamp, so use `file_last_write_utc` as an upper bound
for the last command and set `_time` deliberately (e.g. `collected_at_utc`)
rather than letting the platform guess.

## Triage tips

- Start from `tags`, then read the neighbors: filter by `user` + `history_file`
  and sort by `command_index` to see what ran before and after.
- Check `file_last_write_utc` against the incident window.
- An empty or missing history on a host that clearly ran PowerShell is itself
  worth noting (cleared, disabled, or never interactive).
