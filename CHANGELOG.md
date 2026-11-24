# Changelog

## Unreleased

- Agent: an MCP config whose `npx` (or `pnpm dlx`) argument is empty or starts with a non-ASCII
  character no longer crashes the scan.
- Dependencies: `pubspec.lock` is read, so Dart and Flutter packages are checked against OSV.dev
  (`Pub` ecosystem). Packages from the `sdk` source, like `flutter`, are skipped.
- Secrets: new rule `secret.gitlab-token` (critical) for GitLab personal access tokens (`glpat-` followed by 20 characters).
- Secrets: new rule `secret.huggingface-token` (critical) for Hugging Face access tokens (`hf_` followed by 34 letters).
- Secrets: new rule `secret.npm-token` (critical) for npm access tokens (`npm_` followed by 36 letters or digits).
- Secrets: new rule `secret.mailgun-key` (critical) for Mailgun private API keys (`key-` followed by 32 lowercase hex characters).
- Dependencies: `uv.lock` entries whose `source` is `editable`, `virtual` or `path` (the project itself or a
  local package) are no longer counted or looked up on PyPI.
- Secrets: `secret.url-credentials` skips a connection string whose password is an angle-bracket placeholder
  such as `mongodb+srv://<username>:<password>@host/db`, the form MongoDB Atlas shows in its docs.
- Dependencies: `pnpm-lock.yaml` is read again. A blank line ended the `packages:` section, and
  pnpm writes one right after it, so every pnpm project reported 0 packages checked.

## 1.0.2 (2026-11-23)

- README: GIFs of a real Next.js finding (a password behind `NEXT_PUBLIC_`) and of a clean scan of express.

## 1.0.1 (2026-11-22)

- README and package pages name XSS and SQL injection up front.
- Issue templates (false positive or missed finding, bug, new rule) and a pull request template.

## 1.0.0 (2026-11-22)

- First release. One command scans a repository: `safe-anything .`
- 72 rules in six families: code (SQL and command injection, XSS, eval, SSRF, path traversal,
  unsafe deserialization, weak crypto, TLS checks off, JWT `none`, template injection, debug
  mode), secrets (provider keys, private keys, passwords, credentials in URLs, `.env` files and examples, a `.gitignore` missing `.env`, secrets behind public
  env prefixes like `NEXT_PUBLIC_`),
  agent setups (skipped permissions, pre-approved shell, unpinned MCP servers, plaintext MCP
  tokens, remote MCP over HTTP, `curl | sh` in hooks and skills, prompt-injection text, credential
  file access, invisible Unicode), mobile (Android manifest, WebView, iOS ATS, tokens in plain
  storage), config (Docker, GitHub Actions, Kubernetes, Terraform, nginx) and dependencies
  (nine lockfile formats checked against OSV.dev, with the nearest fixed version).
- Every finding has a file, a line, a severity, a CWE, an OWASP category, a fix and a link to
  read more. Secrets are redacted in the output.
- Terminal report, `--json`, and `--sarif` for GitHub code scanning; `--severity`, `--fail-on`,
  `--offline`, `--include-tests`, `--list-rules`.
- `safe-anything mcp` serves `scan` and `list_rules` to AI agents over MCP (stdio), with a Claude
  Code plugin and an agent skill.
- A GitHub Action that installs the release binary, scans, and writes SARIF.
- `safe-anything:ignore` silences one line; `.safe-anything-ignore` skips paths.
