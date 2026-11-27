<p align="center">
  <img src="docs/assets/logo.png" width="150" height="150" alt="The safe-anything tortoise">
</p>

<h1 align="center">safe-anything</h1>

<p align="center"><b>Find the holes before someone else does.</b><br>
One command finds XSS, SQL injection and other vulnerabilities in your code, leaked secrets,<br>
risky mobile and cloud config, vulnerable dependencies, and the AI agent setup that writes it all.<br>
Every finding comes with the line, the reason and the fix.</p>

<p align="center">
  <img src="https://img.shields.io/github/languages/top/erkamyaman/safe-anything?logo=rust&label=Rust&color=CE422B" alt="Rust share of the code">
  <img src="https://img.shields.io/badge/macOS%20·%20Linux%20·%20Windows-native-2563EB" alt="Native binaries for macOS, Linux and Windows">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-555" alt="MIT license"></a>
  <a href="https://crates.io/crates/safe-anything"><img src="https://img.shields.io/crates/v/safe-anything?color=2FD48F&label=crates.io" alt="crates.io version"></a>
  <a href="https://www.npmjs.com/package/safe-anything"><img src="https://img.shields.io/npm/v/safe-anything?color=2FD48F&label=npm" alt="npm version"></a>
  <br>
  <a href="https://coderabbit.link/er-kam"><img src="https://img.shields.io/coderabbit/prs/github/erkamyaman/safe-anything?labelColor=171717&color=FF570A&label=Reviewed+by+CodeRabbit" alt="Pull requests reviewed by CodeRabbit"></a>
  <a href="https://github.com/erkamyaman/safe-anything"><img src="https://img.shields.io/github/stars/erkamyaman/safe-anything?style=social" alt="GitHub stars"></a>
</p>

<p align="center"><b><a href="#quick-start">Install</a></b> · <a href="https://github.com/erkamyaman/safe-anything/releases">Releases</a> · <a href="#for-ai-agents">Claude Code plugin</a> · <a href="#in-ci">GitHub Action</a> · <a href="docs/rules.md">All 110 rules</a> · <a href="docs/agent-setups.md">Agent setups</a><br>
Made in Türkiye 🇹🇷 by <a href="https://github.com/erkamyaman">erKam Yaman</a>, who also made <a href="https://github.com/erkamyaman/rust-anything">rust-anything</a> · <a href="https://github.com/sponsors/erkamyaman">❤️ Sponsor me</a> · Sponsored by <a href="https://coderabbit.link/er-kam">CodeRabbit</a></p>

<p align="center">
  <img src="docs/assets/terminal.gif" alt="safe-anything scans OWASP Juice Shop: 1,195 files in 0.03 s, 67 findings including the SQL injection in routes/login.ts, eval in routes/userProfile.ts, seeded passwords and a token in localStorage. Then it scans an AI agent setup: a GitHub token in .mcp.json, bypassPermissions, pre-approved Bash, curl piped to sh in a hook, a skill that reads ~/.ssh, invisible Unicode, unpinned MCP servers." width="820">
  <br>
  <sub>A real run on <a href="https://github.com/juice-shop/juice-shop">OWASP Juice Shop</a> and on an agent setup with the usual mistakes (Apple M4). <a href="#measured">What it finds on other repositories</a>.</sub>
</p>

<table>
  <tr>
    <td width="25%" valign="top">
      <b>Your code</b><br>
      SQL and command injection, XSS, <code>eval</code>, SSRF, path traversal, unsafe deserialization, weak crypto. Nine languages and SQL.
    </td>
    <td width="25%" valign="top">
      <b>Your secrets</b><br>
      Cloud and AI keys, tokens, private keys, passwords, and <code>.env</code> mistakes: committed env files, real values in <code>.env.example</code>, secrets behind <code>NEXT_PUBLIC_</code> or <code>VITE_</code>. Always redacted in the output.
    </td>
    <td width="25%" valign="top">
      <b>Your stack</b><br>
      Android and iOS settings, Docker, GitHub Actions, Kubernetes, Terraform, nginx, and every locked dependency against OSV.dev.
    </td>
    <td width="25%" valign="top">
      <b>Your agent</b><br>
      MCP servers, Claude Code, Codex, Cursor, Gemini and OpenCode settings, hooks and skills: the files that decide what your agent may do.
    </td>
  </tr>
</table>

## Quick start

```bash
cargo install safe-anything    # or: npx safe-anything .
safe-anything .
```

That's it. No config, no account, no upload. It exits with 1 when something high or critical is
found, so it works as a pre-commit or CI check as is.

```bash
safe-anything . --json             # machine-readable report
safe-anything . --sarif            # GitHub code scanning
safe-anything . --sarif-file out   # SARIF to the file out, the report on screen
safe-anything . --offline          # no network (skips the dependency check)
safe-anything . --severity medium  # hide low findings
safe-anything . --fail-on never    # always exit 0 (or low, medium, high, critical)
safe-anything . --include-tests    # also report findings in tests and fixtures
safe-anything --list-rules
```

- `.gitignore` is respected. List more paths in `.safe-anything-ignore`; it only adds to what is
  skipped, it cannot bring back what is listed below.
- These are never scanned, and the report only counts the files it did scan:
  - folders `.git`, `node_modules`, `target`, `vendor`, `dist`, `build`, `.next`, `.venv`, `venv`,
    `__pycache__`, `Pods`, `.gradle` and `.claude/worktrees`, so generated code in `build/` is
    not checked
  - any file over 2 MB. Lockfiles are read up to 64 MB, for the dependency check only (no code rules
    past 2 MB); a larger one is named in the report as not checked
  - `*.min.js`, `*.map`, `*.jsonl` and `*.log`
  - binary files: images, fonts, archives, media and compiled files by their extension (`.png`, `.woff2`,
    `.zip`, `.mp4`, `.class`, ...), and any other file with a zero byte in its first 8 KB. A text file
    saved under one of those extensions is not scanned either.
  - `*.lock` files get the dependency check but no code rules
- `safe-anything:ignore` in a comment silences that line (or the next one). Follow it with rule ids,
  `// safe-anything:ignore code.weak-hash, code.eval`, to silence only those rules. An id that is no
  rule (a typo) silences nothing, so the finding stays in the report.
- In tests, specs and fixtures only real provider keys and private keys count, unless you pass
  `--include-tests`.

On a codebase that already has findings, save them once and fail only on new ones:

```bash
safe-anything . --write-baseline .safe-anything-baseline.json
safe-anything . --baseline .safe-anything-baseline.json
```

The baseline holds each finding's rule, path and a SHA-256 of its line, not the line itself, so it
can be committed. A finding counts as known when all three match, wherever the line moved to. Paths
are relative to the scanned folder, so scan the same folder you saved it from. Only files written by
`--write-baseline` are read, not `--json` reports. Review changes to it like code: an entry added to
it hides that finding.

## What it finds

110 rules, each with a CWE id, an OWASP category and a link to the OWASP page that explains it.
The full list is in [docs/rules.md](docs/rules.md).

| | |
| --- | --- |
| **Code** | SQL injection, command injection, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `echo $_GET`, `raw`), `eval` and `new Function`, path traversal, file inclusion from request input, SSRF, open redirects, unsafe deserialization (pickle, `yaml.load`, `ObjectInputStream`, `BinaryFormatter`, `unserialize`, `Marshal`), TLS checks turned off, MD5/SHA-1, DES/RC4/ECB, JWT `none`, template injection, CORS `*`, debug mode, insecure cookies, `Math.random` tokens, `GRANT ALL` and plain-text passwords in SQL files. JS/TS, Python, Go, Java, Kotlin, PHP, Ruby, C#, SQL |
| **Secrets** | AWS (key ids and secret access keys), GitHub, GitLab, Slack, Stripe, Shopify, npm, PyPI, RubyGems, Docker Hub, OpenAI, Anthropic, Groq, Google, Hugging Face, Mailgun, SendGrid, Telegram, DigitalOcean, Heroku, Fly.io, Databricks, Perplexity, OpenRouter, Notion, Twilio, Linear, Prefect, Postman, Pulumi, Sentry, New Relic, Supabase, Grafana and Doppler keys, Google OAuth client secrets, Slack and Discord webhook URLs, private keys (also inside service-account JSON) and age keys, passwords in code, credentials in connection strings, committed `.env` files, real values in `.env.example`, a `.gitignore` that misses `.env`, secrets behind public prefixes (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`) that ship in the client bundle |
| **Agent setups** | `bypassPermissions` and `--dangerously-skip-permissions`, pre-approved `Bash`, `enableAllProjectMcpServers`, MCP servers run with unpinned `npx`/`uvx`/`docker`, MCP tokens in plain text, remote MCP over `http://`, `curl \| sh` in hooks and skills, prompt-injection text, skills that read `~/.ssh` or cloud credentials, invisible Unicode in instructions. [More](docs/agent-setups.md) |
| **Mobile** | Android `debuggable`, `allowBackup`, cleartext traffic, exported content providers, WebView file access and JS bridges, world-readable files; iOS ATS turned off; tokens in UserDefaults, SharedPreferences, AsyncStorage or localStorage |
| **Config** | Docker (unpinned base, root, secrets in `ENV`, `ADD <url>`), `curl \| sh` in scripts, Dockerfiles and workflow `run:` steps, GitHub Actions (`pull_request_target`, `write-all`, actions on `@main`, script injection from PR titles), privileged containers, `hostNetwork`, Terraform (open ingress, public buckets, S3 public access blocks turned off, public or unencrypted databases), nginx autoindex, TLS 1.0/1.1 |
| **Dependencies** | every locked version in `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `go.mod`, `Gemfile.lock`, `composer.lock` and `pubspec.lock`, checked against [OSV.dev](https://osv.dev), with the nearest fixed version |

<p align="center">
  <img src="docs/assets/nextjs-public-env.gif" alt="safe-anything on the with-mqtt-js example from the Next.js repository: 2 high findings, an MQTT password read from a NEXT_PUBLIC_ variable in app/page.tsx and environment.d.ts, which Next.js ships in the client bundle." width="820">
  <br>
  <sub>Of the 73 <a href="https://github.com/vercel/next.js/tree/canary/examples">Next.js examples</a> that come with env files, scanned one by one, the env checks flag one: a password behind <code>NEXT_PUBLIC_</code>.</sub>
</p>

## For AI agents

safe-anything is also an MCP server, so your agent can scan before it commits, and before you
install someone else's skill or MCP server.

```bash
claude mcp add safe-anything -- safe-anything mcp     # Claude Code
codex mcp add safe-anything -- safe-anything mcp      # Codex
```

Or, as a Claude Code plugin with the skill that tells the agent how to triage and fix findings:

```
/plugin marketplace add erkamyaman/safe-anything
/plugin install safe-anything@safe-anything
```

Tools: `scan` (path, offline, severity, include_tests) and `list_rules`. The skill is in
[skills/safe-anything](skills/safe-anything/SKILL.md).

## In CI

```yaml
- uses: erkamyaman/safe-anything@v1.1.0
  with:
    fail-on: high
    # baseline: .safe-anything-baseline.json   # fail only on findings not in it
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: safe-anything.sarif
```

Findings then show up in the repository's Security tab and on pull requests.

## Measured

Release build on an Apple M4, `--offline`, 2026-11-22. Every finding was read by hand. Times are
the scan's own report; the same scan took 0.03 to 0.13 s depending on what else the machine was
doing.

| Repository | Files | Findings | What they are |
| --- | --- | --- | --- |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (vulnerable on purpose) | 1,195 | 67 | the login and search SQL injections, the `eval` challenges, MD5 passwords, tokens in localStorage, seeded passwords, open Terraform ingress; 2 to 3 false positives (a checksum MD5, `innerHTML` with trusted hint text) |
| [DVWA](https://github.com/digininja/DVWA) (vulnerable on purpose) | 233 | 63 | the SQL injections, command injections, MD5 passwords and `eval`; about 4 false positives (setup-script inserts, input validated in the "impossible" level) |
| [expressjs/express](https://github.com/expressjs/express) | 216 | 0 | |
| [pallets/flask](https://github.com/pallets/flask) | 231 | 2 | both false positives in practice: `eval` of the user's own shell startup file, SHA-1 for key derivation (reported as low) |
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | 439 | 1 | `pull_request_target` in a workflow, worth a look |
| [anthropics/skills](https://github.com/anthropics/skills) | 392 | 6 | `innerHTML` in local review pages (5), `shell=True` in a script that runs commands by design |
| [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | 439 | 0 | |
| [rust-anything](https://github.com/erkamyaman/rust-anything) | 3,134 | 6 | `innerHTML` in GIF demo pages (5), an action on `@master` |
| safe-anything itself | 53 | 0 | checked in CI on every push |

<p align="center">
  <img src="docs/assets/express-clean.gif" alt="safe-anything on expressjs/express: no problems found, 216 files scanned in 0.03 s." width="820">
  <br>
  <sub>Quiet on good code: expressjs/express, 216 files, no findings.</sub>
</p>

The noisiest rule is `code.xss-inner-html`: it fires on any HTML built from a variable, and most of
those in local tooling are not reachable by an attacker. It stays on, because real XSS looks the
same. Status per family: [docs/STATUS.md](docs/STATUS.md).

## How it works

One parallel walk over the repository (the `ignore` crate, the walker behind ripgrep), one read per
file, and every rule that applies run as a compiled regex. Where a pattern can't tell right from
wrong, the file is parsed: MCP configs as JSON with comments, Dockerfile stages, and every
lockfile listed under Dependencies. Nothing is executed. The only network call is the dependency check, which sends package
names and versions to OSV.dev ([privacy](docs/privacy.md)).

It finds known patterns; it does not trace data through your program. A clean scan means none of
these 110 problems were found, not that the code is safe. [Design notes](docs/adr).

## Credits

- [OWASP](https://owasp.org): the Top 10, the Top 10 for LLM Applications, MASVS, and the
  [Cheat Sheet Series](https://cheatsheetseries.owasp.org) (CC BY-SA 4.0) that every rule links to.
- [CWE](https://cwe.mitre.org) by MITRE for the weakness ids.
- [OSV.dev](https://osv.dev) for the advisory data.
- [gitleaks](https://github.com/gitleaks/gitleaks) (MIT) for showing how provider tokens are shaped.
- [Craft Anything](https://github.com/storytold/craft-anything) for the idea that every answer should
  show its evidence.
- [How to Secure Anything](https://github.com/veeral-patel/how-to-secure-anything) by Veeral Patel,
  a reading list on security engineering, for the way of thinking about attack surface and least
  privilege.

## Sponsors

<p align="center">
  <a href="https://github.com/erkamyaman/safe-anything">safe-anything</a> is free and open source. If it helps your work, please consider sponsoring it.<br>
  Your support keeps development going.
</p>

<p align="center"><sub>Your safety comes first: sponsors get a logo and a link here, nothing more. No paid recommendations and no setup guides for third-party AI API resellers, so nothing here steers your code, keys or data somewhere you didn't choose.</sub></p>

<p align="center">
  <a href="https://coderabbit.link/er-kam">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/sponsors/company-dark.svg">
      <img src="docs/assets/sponsors/company-light.svg" width="800" alt="Company sponsor: CodeRabbit">
    </picture>
  </a>
</p>

<p align="center">
  <a href="https://github.com/sponsors/erkamyaman">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/assets/sponsors/sponsors-dark.svg">
      <img src="docs/assets/sponsors/sponsors-light.svg" width="800" alt="Sponsors: Santosh Yadav, Hakan Soytürk, Ali Yilmaz, Ashley Hunter, Fatih Uzuntaş, bugrcvi">
    </picture>
  </a>
</p>

<p align="center">
  <a href="https://github.com/sponsors/erkamyaman"><img src="https://img.shields.io/badge/Become_a_sponsor-%E2%9D%A4-db61a2?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Become a sponsor"></a>
  <a href="https://buymeacoffee.com/erkamyaman"><img src="https://img.shields.io/badge/Buy_me_a_coffee-%E2%98%95-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy me a coffee"></a>
</p>

## Contributing

The most useful contribution is a fixture: a few lines safe-anything gets wrong. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
