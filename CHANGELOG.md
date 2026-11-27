# Changelog

## Unreleased

- Secrets: `secret.env-file` and `secret.env-example-value` no longer report file paths starting
  with `/`, `./`, `../` or `~/` on variables ending in `_FILE`, `_PATH` or `_DIR` or named `PWD`
  (`POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password`, `PRIVATE_KEY_PATH=./certs/server.key`,
  `PWD=/srv/app/releases/current`), while still reporting non-path values and `/`-prefixed secrets
  on other secret variables.
- Code: `code.sql-injection` no longer reports JavaScript and TypeScript tagged templates
  (``sql`SELECT * FROM users WHERE id = ${id}` ``, `Prisma.sql`, `prisma.$queryRaw`,
  ``sql<Row[]>`...` ``). The tag receives the values apart from the query text and binds them.
  An untagged template literal and a raw tag (`String.raw`, `sql.raw`, `sql.unsafe`) are still
  reported.
- Secrets: `secret.hardcoded-password` no longer lets a placeholder-like value elsewhere on the
  line hide a real password. The placeholder check now only looks at the value right after the
  matched name, so `connect(user="testuser", password="...")` and
  `{"env": "none", "password": "..."}` are reported, while a placeholder in the password's own
  value stays quiet.
- Secrets: `secret.env-file` and `secret.env-example-value` now also match variable names where
  `PASS` or `PWD` is a whole `_`-separated word (`DB_PASS`, `SMTP_PASS`, `PASS_FILE`, `MYSQL_PWD`),
  while keeping names like `PASSPORT_ID`, `BYPASS_CACHE` and `COMPASS_URL` quiet.
- Secrets: new rule `secret.prefect-api-key` (critical) for Prefect API keys (`pnu_` followed by 36
  letters and digits).
- Secrets: new rule `secret.openrouter-key` (critical) for OpenRouter API keys (`sk-or-v1-` followed
  by 64 lower-case hex characters).
- Secrets: new rule `secret.newrelic-key` (critical) for New Relic user API keys (`NRAK-` followed
  by 27 upper-case letters and digits).
- Secrets: new rule `secret.flyio-token` (critical) for Fly.io access tokens (`fo1_` followed by 43
  letters, digits, `_` or `-`).
- Report: the summary line says `Scanned 1 file` and `1 package checked against OSV.dev` for a
  count of one; other counts stay plural.
- Code: the JavaScript and Python patterns in `code.sql-injection` now also match escaped
  newlines, tabs and carriage returns (`\n`, `\t`, `\r`) inside quoted query strings
  (`db.query("SELECT id\nFROM users WHERE id = " + id)`,
  `cur.execute("SELECT id\nFROM users WHERE id = %s" % uid)`).
- Code: the Java, Kotlin and C# concatenation patterns in `code.sql-injection` now also match
  escaped newlines, tabs and carriage returns (`\n`, `\t`, `\r`) inside quoted query strings
  (`"SELECT id\nFROM users WHERE id = " + id`).
- Code: the Go `fmt.Sprintf` pattern in `code.sql-injection` now uses the same SQL clause keyword
  check (`SELECT ... FROM`, `INSERT INTO`, `UPDATE ... SET`, `DELETE FROM`) as the other SQL
  injection rules and also matches raw backtick query strings and escaped newlines or tabs
  (`"SELECT id\nFROM users WHERE id = %s"`), so ordinary messages starting with words like
  `"updated: %d nodes"`, `"selection is larger than %d bytes"`, `"Deletes %s"` or
  `"update check returned %d"` are no longer reported. `UPDATE` in every SQL injection rule now
  also matches schema-qualified tables and aliases (`UPDATE public.users u SET`).
- Secrets: new rule `secret.heroku-key` (critical) for Heroku API keys (`HRKU-AA` followed by 58
  letters, digits, `_` or `-`).
- Secrets: new rule `secret.notion-token` (critical) for Notion integration tokens (`ntn_`
  followed by 11 digits and 35 letters or digits).
- Secrets: new rule `secret.perplexity-key` (critical) for Perplexity API keys (`pplx-`
  followed by 48 letters and digits).
- Secrets: new rule `secret.dockerhub-token` (critical) for Docker Hub personal access tokens
  (`dckr_pat_` followed by 27 letters, digits, `_` or `-`).
- Secrets: new rule `secret.age-key` (critical) for age private keys (`AGE-SECRET-KEY-1` and
  post-quantum `AGE-SECRET-KEY-PQ-1` followed by 58 upper-case Bech32 characters), which decrypt
  every file encrypted to them, SOPS files included.
- Secrets: when a line holds more than one secret or more than one finding, all secrets on that
  line are now masked in every finding on it (two tokens of one kind, tokens of different kinds, a
  token beside a `NEXT_PUBLIC_` or `VITE_` secret, another rule's finding on the same line such as
  `code.eval`, and MCP configs with several keys or JSON-escaped values on one line). Findings on
  such lines get a new baseline hash and show once as new; run `--write-baseline` again.
- Secrets: new rule `secret.databricks-token` (critical) for Databricks personal access tokens (`dapi`
  followed by 32 lowercase hex characters, optionally followed by `-` and one digit such as `-2`).
- Secrets: `secret.env-file` and `secret.env-example-value` now catch values followed by an inline
  `#` comment (quoted or unquoted), leaving the comment out of the masked snippet. A `#` inside an
  unquoted value with no space before it stays part of the value, and placeholders followed by a
  comment (`your-key-here # set me`, `**************** # masked`) remain quiet.
- Secrets: `secret.gitlab-token` also finds GitLab deploy tokens (`gldt-` and 20 letters, digits, `_` or `-`)
  and pipeline trigger tokens (`glptt-` and 40 lowercase hex).
- Secrets: `secret.slack-token` also finds Slack app-level tokens (`xapp-1-A0123...-1234567890123-` and
  lowercase letters and digits), which let a Socket Mode app connect as the app. A bare `xapp-` stays quiet.
- Secrets: `secret.env-file` and `secret.env-example-value` stay on one line instead of matching
  across line breaks, so an empty assignment like `API_KEY=` followed by another variable is no
  longer reported, a blank line above a placeholder like `your-placeholder-key-here` no longer
  breaks placeholder skipping, and a real secret after a blank line is reported on its own line
  instead of the blank line above it.
- Config and agent files: `remote-script` also reports a shell option with a value before `-c`
  (`bash -o pipefail -c "$(curl ...)"`, `sh -e -o nounset -c ...`) and sudo flags combined with a
  value flag in one word (`curl ... | sudo -Eu root bash`, `sudo -HEu "$USER" bash`,
  `sudo -ED"/tmp/build dir" sh`). `curl ... | sudo -uroot; bash` is no longer reported, since that
  `bash` is a separate command.
- Config: `config.gha-script-injection` skips a commented-out workflow line like
  `# - run: echo "${{ github.event.pull_request.title }}"`. A `#` line inside a `run: |` or `script: |`
  block is still reported, since the expression is filled in before the shell sees the comment.
- Config: `config.gha-script-injection` also checks `workflow_run` workflows, so
  `github.event.workflow_run.head_branch`, `.display_title`, `.head_commit.message` and the head commit's
  author and committer name and email pasted into a `run:` step are reported. Fields the triggering run
  can't set, like `workflow_run.id`, `.conclusion` or `.repository.name`, are not.
- Dependencies: a lockfile over 2 MB is read again (up to 64 MB) instead of being skipped with "0 packages
  checked". A larger one is named in the report (`lockfiles_too_large` in JSON). npm, Composer and Pipfile
  lockfiles are also read in one pass, whatever their key order: 0.12 s instead of 4.3 s for a 3 MB
  package-lock.json, 0.5 s for 60 MB.
- Config: `config.weak-tls-version` reads Apache's `SSLProtocol` signs, so `all -SSLv3 -TLSv1 -TLSv1.1` is no
  longer reported, while `all -SSLv3` (TLS 1.0 still on) and `+TLSv1.1` still are. A plain name replaces the set
  so far, as Apache does, so `TLSv1.2 TLSv1` is reported and `TLSv1 TLSv1.2` is not. A line that names an old
  version and goes on after a backslash, uses a `${VAR}` or has an unknown word is still reported.
- Secrets: `secret.linear-api-key` finds Linear API keys (`lin_api_` and 40 letters and digits) and
  `secret.postman-api-key` finds Postman API keys (`PMAK-`, 24 hex, `-`, 34 hex). Both are critical.
- Secrets: new rule `secret.pulumi-token` (critical) for Pulumi access tokens (`pul-` followed by 40 lowercase hex characters).
- Config and agent: `remote-script` also reports `curl ... | sudo -E bash` (sudo with flags, as in NodeSource's
  install line) and a shell run on a downloaded script, `bash -c "$(curl ...)"` and its backtick form. `sudo tee`
  and a `$(curl ...)` only assigned to a variable stay quiet, as does `sudo -E tee bash` (tee runs, not bash).
  PowerShell's `iwr`, `Invoke-WebRequest`, `irm`, `Invoke-RestMethod`, `iex` and `Invoke-Expression`, and its
  `curl` and `wget` aliases, match in any case, so `irm https://... | iex` is reported.
- Build: the pinned `cookie` (0.18.3) and `time` (0.3.47) crates are updated for RUSTSEC-2026-0594 and
  RUSTSEC-2026-0009. Neither was reachable from a scan.
- Secrets: four new critical rules. `secret.sentry-token` finds Sentry user auth tokens (`sntryu_` and 64
  lowercase hex), `secret.supabase-token` Supabase access tokens (`sbp_` and 40 lowercase hex),
  `secret.grafana-token` Grafana service account tokens (`glsa_`, 32 letters or digits, `_`, 8 hex) and
  `secret.doppler-token` Doppler personal tokens (`dp.pt.` and 43 letters or digits).
- Secrets: new rule `secret.rubygems-token` (critical) for RubyGems API keys (`rubygems_` followed by 48 lowercase hex characters).

## 1.1.0 (2026-11-25)

- Agent: `agent.mcp-plaintext-secret` also checks the `headers` and `http_headers` of remote MCP servers
  in JSON configs. `Authorization` and `Proxy-Authorization` always count. In `env` and headers alike, a
  value is judged after its auth scheme and with its variables taken out: `Bearer ${API_TOKEN}` and
  `user:${PASSWORD}` are skipped, `admin:<password>@${DB_HOST}` and `${TOKEN:-sk_live_...}` are
  reported.
- Agent: `agent.unrestricted-shell` now reads `permissions.allow` in `.claude/settings*.json` instead of matching `"Bash"` anywhere in the file, so entries in `deny`, `ask`, or hook matchers are no longer flagged.
- Agent: more agent files are read: `.clinerules` (a file or a folder), `.windsurf/rules/`, `.github/instructions/*.instructions.md`,
  `.github/prompts/*.prompt.md`, `.roo/rules/` and `.kiro/steering/` for instructions, and Windsurf's `mcp_config.json`,
  `cline_mcp_settings.json`, and Zed's `.zed/settings.json` and `.config/zed/settings.json` (`context_servers`) for MCP servers.
- Agent: `agent.mcp-unpinned` skips the value of flags like `--python` (`uvx`, `pipx run`) and `--user`
  or `--platform` (`docker run`, `podman run`), so `uvx --python 3.12 pkg==1.0` no longer reports `3.12`
  and `docker run -u 1000:1000 acme/mcp` reports `acme/mcp`. An empty `docker run` argument is skipped.
- Secrets: `secret.env-not-ignored` is reported at the `.env` file when the project has no `.gitignore`
  at all. Example files like `.env.example` alone no longer trigger it.
- Secrets: `secret.env-not-ignored` reads `.gitignore` the way git does, so only a line that really ignores
  `.env` counts. `.envrc`, `.env.local`, `.env/`, `# .env` or a later `!.env` no longer hide it.
- Secrets: `secret.env-file` and `secret.env-example-value` now catch base64 values ending in `=` padding and
  passwords with `!@#$%^&*`. A value that is only `*` characters or starts with `$` (a reference like
  `$POSTGRES_PASSWORD`) is skipped.
- Secrets: `secret.public-env-secret` now replaces everything after the variable name on its line with `****`,
  so its finding no longer prints the value, however it is written (`=`, `:`, `=>`,
  `||`, `ENV NAME value`, ...). Before, the whole line was printed as is. Masking now keeps at most a third of a
  secret, so a short value is not printed whole.
- Agent: an MCP config whose `npx` (or `pnpm dlx`) argument is empty or starts with a non-ASCII
  character no longer crashes the scan.
- Scan: minified bundles, source maps, `.jsonl` and `.log` files, and images, fonts, archives, media and
  compiled files (`png`, `woff2`, `zip`, `mp4`, `class`, ...) are skipped by name without being opened.
  Other binary files are left after their first 8 KB instead of being read in full.
- Agent: `agent.mcp-plaintext-secret` no longer takes an env key for a secret when its credential word is
  only part of an ordinary word, so `PATH`, `PYTHONPATH`, `NODE_PATH`, `DISPATCH_MODE`, `AUTHOR`,
  `MONKEY_PATCH` and `KEYCHAIN_PROFILE` are not reported. `GITHUB_PAT`, `githubPat`, `OPENAI_APIKEY`,
  `daemonKey`, `patHash` and `clientSecret` still are.
- Agent: `agent.mcp-insecure-url` now reads a bracketed IPv6 host up to its closing `]` (only `[::1]` counts as local) and matches `http://` without regard to case.
- Dependencies: `pubspec.lock` is read, so Dart and Flutter packages are checked against OSV.dev
  (`Pub` ecosystem). Packages from the `sdk` source, like `flutter`, are skipped.
- Secrets: new rule `secret.gitlab-token` (critical) for GitLab personal access tokens (`glpat-` followed by 20 characters).
- Secrets: new rule `secret.huggingface-token` (critical) for Hugging Face access tokens (`hf_` followed by 34 letters).
- Secrets: new rule `secret.npm-token` (critical) for npm access tokens (`npm_` followed by 36 letters or digits).
- Secrets: new rule `secret.mailgun-key` (critical) for Mailgun private API keys (`key-` followed by 32 lowercase hex characters).
- Secrets: new rule `secret.telegram-bot-token` (high) for Telegram bot tokens (8 to 10 digits, a colon, then 35 letters, digits, `_` or `-`).
- Secrets: new rule `secret.aws-secret-key` (critical) for AWS secret access keys: a 40-character value assigned to a name with `aws` and `secret` in it
  (`aws_secret_access_key = ...`, `AWS_SECRET_ACCESS_KEY=...`, `"awsSecretAccessKey": "..."`). Values that can't be a random key are
  skipped: the AWS docs example key, hashes, paths, words like `TestSecretKey...`, `000...` and other repeats.
- Secrets: new rule `secret.twilio-api-key` (critical) for Twilio API keys (`SK` followed by 32 lowercase hex characters).
- Secrets: new rule `secret.digitalocean-token` (critical) for DigitalOcean tokens (`dop_v1_`, `doo_v1_` or `dor_v1_` followed by 64 lowercase hex characters).
- Secrets: new rule `secret.shopify-token` (critical) for Shopify access tokens (`shpat_`, `shpca_`, `shppa_` or `shpss_` followed by 32 hex characters).
- Secrets: new rule `secret.pypi-token` (critical) for PyPI upload tokens (`pypi-AgEIcHlwaS5vcmc` followed by 50 or more characters).
- Secrets: new rule `secret.sendgrid-key` (critical) for SendGrid API keys (`SG.`, 22 characters, a dot, then 43 characters).
- Secrets: new rule `secret.discord-webhook` (high) for Discord webhook URLs (`discord.com/api/webhooks/` or `discordapp.com/api/webhooks/`, a 17 to 20 digit id, then a token of 60 or more characters).
- Secrets: new rule `secret.slack-webhook` (high) for Slack incoming webhook URLs (`hooks.slack.com/services/T…/B…/` and a 24-character token). The docs placeholder with `T00000000` or `XXXXXXXX` is skipped.
- Config: new rule `config.tf-public-access-block` (medium) for `block_public_policy = false` or
  `restrict_public_buckets = false` in an `aws_s3_bucket_public_access_block` or `aws_s3_account_public_access_block`.
- Secrets: new rule `secret.groq-key` (critical) for Groq API keys (`gsk_` followed by 52 letters or digits).
- Code: new rule `code.open-redirect` (medium) for redirects built straight from request input (`res.redirect(req.query.next)`, `redirect(request.args.get("next"))`); a redirect to a fixed path stays unflagged.
- CLI: `--sarif-file <FILE>` writes SARIF to a file from the same scan that prints the report and sets the
  exit code. The GitHub Action uses it, so it scans (and asks OSV.dev) once instead of twice.
- Config: new rules `config.tf-public-database` (high) for `publicly_accessible = true` and `config.tf-unencrypted-storage` (medium)
  for `storage_encrypted = false` in Terraform files. `publicly_accessible = false`, `storage_encrypted = true` and commented-out lines stay unflagged.
- Config: `config.remote-script` also checks GitHub Actions workflows, so a `run:` step (or a line in a
  `run: |` block) that pipes `curl` or `wget` into a shell is reported. `curl -o file URL`, a step `name:` and a
  commented-out line are not.
- Code: `code.sql-injection` also catches Go queries built by concatenation in `db.Query`, `db.QueryRow`, `db.Exec`
  and their `Context` variants (`db.Query("SELECT * FROM t WHERE id=" + id)`). A query with a placeholder stays unflagged.
- Code: `code.ssrf` also covers Go (`http.Get`, `http.Head`, `http.Post` with `r.FormValue(...)` or `r.URL.Query().Get(...)`)
  and PHP (`file_get_contents`, `curl_init`, `fopen` with `$_GET`, `$_POST` or `$_REQUEST`). A fixed URL stays unflagged.
- Code: `code.open-redirect` now also matches a status code first, so `res.redirect(301, req.query.next)` is reported; a redirect to a fixed path stays unflagged.
- Dependencies: `uv.lock` entries whose `source` is `editable`, `virtual` or `path` (the project itself or a
  local package) are no longer counted or looked up on PyPI.
- Dependencies: `Gemfile.lock` gems from `GIT` and `PATH` sections (a git repository or a local folder) are
  no longer counted or looked up on RubyGems. Only gems in `GEM` sections are.
- Secrets: `secret.url-credentials` skips a connection string whose password is an angle-bracket placeholder
  such as `mongodb+srv://<username>:<password>@host/db`, the form MongoDB Atlas shows in its docs.
- Secrets: `secret.private-key` also finds a key written with `\n` escapes inside a string, the way a Google
  service-account JSON file stores it. The whole key body is masked in the output.
- Dependencies: `pnpm-lock.yaml` is read again. A blank line ended the `packages:` section, and
  pnpm writes one right after it, so every pnpm project reported 0 packages checked.
- Agent: new rule `agent.mcp-auto-approve` (high) for `"enableAllProjectMcpServers": true` in
  `.claude/settings*.json`, which starts every MCP server in the project's `.mcp.json` without asking about
  each one.
- CLI: `safe-anything:ignore` takes an optional list of rule ids (`// safe-anything:ignore code.weak-hash, code.eval`)
  and then silences only those rules on that line and the next. An unknown id silences nothing. A bare marker
  still silences every rule.
- CLI: `--write-baseline <file>` records the current findings (rule, path and a SHA-256 of the line, no code or
  secrets), and `--baseline <file>` hides them, wherever the line moved to, and says how many it hid, so CI can
  fail only on new findings. The action has a `baseline` input for it.
- CLI: `--sarif` writes paths from the working directory, not from the scanned folder, so
  `safe-anything app --sarif` (or the action's `path: app`) gives `app/src/x.js` and code scanning finds
  the file. The terminal and `--json` reports keep paths relative to the scanned folder.
- CLI: SARIF rules have a `fullDescription` and a `help` text (the fix, the CWE and OWASP category, and the
  link), so a GitHub code scanning alert shows the fix in its side panel. `--list-rules --json` and the MCP
  `list_rules` tool include each rule's `fix`.
- CLI: `safe-anything --help` now shows a few examples, including `safe-anything mcp`, and how to ignore a finding (`safe-anything:ignore` or `.safe-anything-ignore`).
- Secrets: new rule `secret.google-oauth-secret` (high) for Google OAuth client secrets (`GOCSPX-` followed by 28 letters, digits, `_` or `-`).
- Dependencies: `Pipfile.lock` is read, so Pipenv projects are checked against OSV.dev (`PyPI` ecosystem), `default` and `develop` packages alike. Entries from git, a path or an editable install are skipped.

Thanks to everyone who contributed to this release: @OnurrUgur, @ghozali25, @Prashaxt, @MaxonT, @gasparoff, @sniwas, @lyn1dev, @brixtonpham, @jay23606, @tridev-tej, @pethapixels-create and @PrajsRamteke.

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
