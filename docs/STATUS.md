# Status

What works, and how it was last checked. Updated 2026-11-22.

**Verified**: run on real code someone else wrote, every finding read by hand. **Tested**: covered
by this repository's tests (a fixture per family with safe look-alikes that must not be flagged).

## Families

| Family | Status | Last real run | Result |
| --- | --- | --- | --- |
| Code | Verified | OWASP Juice Shop, DVWA, express, flask (2026-11-22) | finds the known SQL injections, command injections and `eval` in Juice Shop and DVWA; 0 findings in express; the noisiest rule is `code.xss-inner-html` |
| Secrets | Verified | Juice Shop seeded users, rust-anything, the 73 Next.js examples that ship env files, each scanned as its own project (2026-11-22) | seeded passwords found; placeholders (`xoxp-...`, `****`, `${VAR}`, `your-key-here`) ignored; in the Next.js examples the env checks flag one project, a password behind `NEXT_PUBLIC_` that ships to the browser, and nothing else |
| Agent setups | Verified | anthropics/skills, vercel-labs/agent-skills, a real `~/.claude` (2026-11-22) | no false prompt-injection hits left on skills that warn against injection; MCP-config checks tested on fixtures only |
| Mobile | Tested | none | Android manifest, network security config, WebView, iOS plist, storage on fixtures |
| Config | Verified | Juice Shop Terraform and workflows, modelcontextprotocol/servers (2026-11-22) | open ingress, `pull_request_target`, unpinned actions found; build-stage `FROM` and action inputs no longer flagged |
| Dependencies | Verified | the dependency fixture against live OSV.dev (2026-11-22) | 13 packages in six ecosystems, real advisories, nearest fixed version |

## Outputs

| Output | Status | Notes |
| --- | --- | --- |
| Terminal | Tested | `tests/cli.rs` |
| `--json` | Tested | `tests/cli.rs` |
| `--sarif` | Tested | shape checked in `tests/cli.rs`; not yet uploaded to GitHub code scanning |
| `--sarif-file` | Tested | `tests/cli.rs`: same SARIF as `--sarif`, written by the run that prints the report and sets the exit code |
| MCP (`safe-anything mcp`) | Tested | initialize, tools/list, tools/call over stdio in `tests/cli.rs`; not yet run inside an agent |
| GitHub Action (`action.yml`) | Not run | needs a published release to download |

## Known limits

- Patterns, not data flow: a command built in one statement and run in another is not flagged.
- Each finding sees one line; multi-line SQL strings are matched only on the line the keyword is on.
- No Swift, Kotlin or Rust code rules yet (beyond mobile storage and WebView checks).
