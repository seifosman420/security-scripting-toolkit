# security-scripting-toolkit

Small, tested scripts for security operations, incident response and threat
hunting. Each script ships with documented behavior, limitations, synthetic
test fixtures and automated tests. Companion to
[detections-as-code](../detection-lab).

> All test data is synthetic (example.com, fictional users). Nothing here
> contains real logs. Use scripts only on systems you are authorized to access.

## Scripts

| Script | What it does | Platform | Status |
|---|---|---|---|
| [Export-PSHistory](scripts/powershell/Export-PSHistory/) | Collect PowerShell history from all user profiles into one searchable JSONL/CSV file | PowerShell 5.1 / 7+ | experimental |

## Layout

```
scripts/<language>/<Script-Name>/
├── <Script-Name>.ps1     # the tool
├── README.md             # usage, output schema, design notes, LIMITATIONS
├── SEARCHING.md          # how to use the output (if applicable)
├── examples/             # synthetic sample output
└── tests/                # fixtures generator + dependency-free test runner
docs/
├── approach.md                 # how I write security scripts
└── script-readme-template.md   # template for new scripts
```

## Run the tests

```powershell
pwsh ./scripts/powershell/Export-PSHistory/tests/Test-ExportPSHistory.ps1
```

## Standards for every script

1. Read-only by default. Anything that changes a system is opt-in and explicit.
2. Structured output (JSONL/CSV), not pretty text.
3. Provenance in the data: host, user, source, hashes, collection time.
4. Partial failure is reported, not fatal and not silent.
5. Limitations are documented, including what the script cannot see.
6. Tested against synthetic fixtures, including awkward input.

See [docs/approach.md](docs/approach.md).
