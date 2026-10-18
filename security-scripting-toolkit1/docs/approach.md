# How I write security scripts

## Before writing code

- **Name the question.** "What did PowerShell run on this host, by whom?" A
  script answers one question well; a toolkit answers many.
- **Know the artifact.** Where does the data live, who writes it, what is its
  format, what does it *not* record? (PSReadLine history: no timestamps.)
  Write the limitations before the code.
- **Decide the consumer.** Analyst at a terminal, SIEM, spreadsheet, another
  script? That decides the output format. Default: JSONL, with CSV as an option.

## Design rules

| Rule | Why |
|---|---|
| Read-only by default | Evidence handling. Never alter what you collect |
| Open files shared-read | Live systems have files in use |
| One record per fact, flat fields | Greppable, loadable anywhere |
| Provenance on every record | Host, user, source path, hash, collection time |
| Hash inputs and output | Chain of custody, tamper evidence |
| Errors collected and reported, run continues | One locked profile must not abort triage |
| Refuse to overwrite without `-Force` | Don't destroy earlier collections |
| No network calls, no external dependencies | Safe on isolated or compromised hosts |
| UTF-8 without BOM | Predictable for downstream tools |
| Target the oldest supported runtime | Windows PowerShell 5.1 is still everywhere in IR |
| Warn on missing privileges | Silent partial collection is the worst failure |

## Testing approach

- **Synthetic fixtures generated at test time**, not committed real data.
- **Cover awkward input:** CRLF vs LF, BOM, blank lines, non-ASCII, empty
  files, missing files, duplicate paths, multi-line records.
- **Assert the safety properties,** not just the output: sources unchanged,
  no overwrite, hash sidecar valid.
- **Mutation-check the tests.** Deliberately break the code and confirm tests
  fail. A test suite that cannot fail proves nothing.
- **Make the script importable** (guard `main` so dot-sourcing loads only the
  functions) so units are testable without running the tool.
- Test on every runtime you claim to support.

## Documenting

Every script README states: purpose, usage, output schema, design notes,
**limitations**, and how it was tested. If a limitation would change an
investigator's conclusion (e.g. "no timestamps"), put it near the top.

## Ethics and safety

- Authorized use only; say so in the README.
- Collected data can hold secrets. Say so, and handle output accordingly.
- Do not add offensive capability (credential dumping, evasion) to a
  collection toolkit. Keep scope defensive.

## Review checklist

- [ ] Does it modify anything it reads?
- [ ] What happens with no admin rights? Empty input? Locked file? Huge file?
- [ ] Works on the oldest runtime I claim?
- [ ] Output loads cleanly in jq / DuckDB / PowerShell?
- [ ] Limitations and sensitivity documented?
- [ ] Tests fail when I break the code?
