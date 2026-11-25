mod common;

use std::path::Path;
use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn fixture(name: &str) -> String {
    common::fixtures().join(name).to_string_lossy().into_owned()
}

#[test]
fn json_output_lists_every_finding_and_fails_on_high() {
    let (code, out) = run(&[&fixture("code"), "--json", "--offline"]);
    let report: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let expected = std::fs::read_to_string(Path::new(&fixture("code")).join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .count();
    assert_eq!(report["findings"].as_array().unwrap().len(), expected);
    let first = &report["findings"][0];
    for key in [
        "rule", "severity", "path", "line", "message", "fix", "snippet",
    ] {
        assert!(!first[key].is_null(), "finding has {key}");
    }
    assert_eq!(report["dependency_check"]["status"], "skipped");
    assert_eq!(code, 1);
}

#[test]
fn terminal_report_shows_file_line_rule_and_fix() {
    let (_, out) = run(&[&fixture("agent"), "--offline"]);
    assert!(out.contains(".mcp.json:5"), "{out}");
    assert!(out.contains("agent.mcp-unpinned"), "{out}");
    assert!(out.contains("Pin an exact version"), "{out}");
    let expected = std::fs::read_to_string(Path::new(&fixture("agent")).join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .count();
    assert!(
        out.lines()
            .any(|l| l.starts_with(&format!("{expected} findings"))),
        "{out}"
    );
}

#[test]
fn fail_on_and_severity_filter() {
    let (code, _) = run(&[&fixture("config"), "--offline", "--fail-on", "never"]);
    assert_eq!(code, 0);
    let (_, out) = run(&[
        &fixture("config"),
        "--offline",
        "--json",
        "--severity",
        "high",
    ]);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["severity"] == "high" || f["severity"] == "critical")
    );
}

#[test]
fn clean_folder_exits_zero_and_says_so() {
    let dir = std::env::temp_dir().join(format!("safe-anything-clean-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.py"), "print('hello')\n").unwrap();
    let (code, out) = run(&[dir.to_str().unwrap(), "--offline"]);
    assert_eq!(code, 0);
    assert!(out.contains("No problems found"), "{out}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn every_rule_has_a_cwe_and_a_reference() {
    let (_, out) = run(&["--list-rules", "--json"]);
    let rules: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let rules = rules.as_array().unwrap();
    assert!(rules.len() >= 69);
    for r in rules {
        assert!(
            r["cwe"].as_str().is_some_and(|c| c.starts_with("CWE-")),
            "{r}"
        );
        assert!(
            r["learn_more"]
                .as_str()
                .is_some_and(|u| u.starts_with("https://")),
            "{r}"
        );
        assert!(r["fix"].as_str().is_some_and(|f| !f.is_empty()), "{r}");
    }
}

#[test]
fn sarif_file_written_by_the_same_run_as_the_report() {
    let dir = std::env::temp_dir().join(format!("safe-anything-sarif-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out.sarif");
    let file = file.to_str().unwrap();
    let (_, sarif) = run(&[
        &fixture("code"),
        "--offline",
        "--sarif",
        "--fail-on",
        "never",
    ]);
    // The terminal report on stdout, SARIF in the file, and --fail-on applied.
    let (code, out) = run(&[&fixture("code"), "--offline", "--sarif-file", file]);
    assert_eq!(code, 1);
    assert!(out.contains("findings"), "{out}");
    assert_eq!(std::fs::read_to_string(file).unwrap(), sarif);
    // --severity filters both outputs the same way, and --json still works.
    let (_, sarif) = run(&[
        &fixture("code"),
        "--offline",
        "--sarif",
        "--severity",
        "critical",
    ]);
    let (code, out) = run(&[
        &fixture("code"),
        "--offline",
        "--json",
        "--severity",
        "critical",
        "--fail-on",
        "never",
        "--sarif-file",
        file,
    ]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(
        written["runs"][0]["results"].as_array().unwrap().len(),
        report["findings"].as_array().unwrap().len()
    );
    assert_eq!(std::fs::read_to_string(file).unwrap(), sarif);
    // A file that can't be written is an error, not a silent success.
    let missing = dir.join("no-such-dir").join("out.sarif");
    let (code, _) = run(&[
        &fixture("code"),
        "--offline",
        "--fail-on",
        "never",
        "--sarif-file",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(code, 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn sarif_output_for_code_scanning() {
    let (_, out) = run(&[&fixture("code"), "--sarif", "--offline"]);
    let sarif: serde_json::Value = serde_json::from_str(&out).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "safe-anything");
    let expected = std::fs::read_to_string(Path::new(&fixture("code")).join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .count();
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), expected);
    let r = &results[0];
    assert!(r["ruleId"].as_str().is_some());
    assert!(
        r["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap()
            >= 1
    );
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(rules.iter().any(|d| d["id"] == r["ruleId"]));
    for d in rules {
        let text = |v: &serde_json::Value| v.as_str().filter(|s| !s.is_empty()).is_some();
        assert!(text(&d["fullDescription"]["text"]), "{d}");
        assert!(text(&d["help"]["text"]), "{d}");
        assert!(text(&d["help"]["markdown"]), "{d}");
        for field in ["text", "markdown"] {
            let help = d["help"][field].as_str().unwrap();
            assert!(help.contains("CWE-"), "{d}");
            assert!(help.contains(d["helpUri"].as_str().unwrap()), "{d}");
        }
    }
}

#[test]
fn sarif_rule_help_has_the_fix() {
    let (_, out) = run(&[&fixture("agent"), "--sarif", "--offline"]);
    let sarif: serde_json::Value = serde_json::from_str(&out).unwrap();
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let shell = rules
        .iter()
        .find(|d| d["id"] == "agent.unrestricted-shell")
        .expect("agent.unrestricted-shell in the agent fixture");
    let help = shell["help"]["text"].as_str().unwrap();
    assert!(help.contains("Allow specific commands"), "{shell}");
    assert!(help.contains("LLM06:2025 Excessive Agency"), "{shell}");
    let markdown = shell["help"]["markdown"].as_str().unwrap();
    assert!(markdown.contains("Bash(npm test:\\*)"), "{shell}");
}

#[test]
fn sarif_paths_are_relative_to_the_working_directory() {
    let dir = std::env::temp_dir().join(format!("safe-anything-sarif-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("app/src")).unwrap();
    std::fs::write(dir.join("app/src/x.js"), "eval(req.query.code);\n").unwrap();
    let uri = |cwd: &Path, args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
            .args(args)
            .args(["--sarif", "--offline"])
            .current_dir(cwd)
            .output()
            .unwrap();
        let sarif: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(uri(&dir, &["app"]), "app/src/x.js");
    assert_eq!(uri(&dir, &["./app/"]), "app/src/x.js");
    assert_eq!(uri(&dir, &["app/src/x.js"]), "app/src/x.js");
    assert_eq!(
        uri(&dir, &[dir.join("app").to_str().unwrap()]),
        "app/src/x.js"
    );
    assert_eq!(uri(&dir.join("app"), &["."]), "src/x.js");
    assert_eq!(uri(&dir.join("app/src"), &["../src"]), "x.js");
    // The terminal report keeps paths relative to the scanned folder.
    let (_, out) = run(&[dir.join("app").to_str().unwrap(), "--offline"]);
    assert!(out.contains(" src/x.js:1 "), "{out}");
    let file = dir.join("out.sarif");
    let out = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
        .args(["app", "--offline", "--fail-on", "never", "--sarif-file"])
        .arg(&file)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains(" src/x.js:1 "));
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "app/src/x.js"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn baseline_hides_known_findings_only() {
    let dir = std::env::temp_dir().join(format!("safe-anything-baseline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let app = dir.join("app.js");
    let baseline = dir.join(".safe-anything-baseline.json");
    let scan = |extra: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
            .arg(&dir)
            .arg("--offline")
            .args(extra)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let found = |out: &str| -> Vec<(String, String, u64)> {
        let report: serde_json::Value = serde_json::from_str(out).unwrap();
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["path"].as_str().unwrap().into(),
                    f["rule"].as_str().unwrap().into(),
                    f["line"].as_u64().unwrap(),
                )
            })
            .collect()
    };
    let eval = "const f = eval(req.body.code);\n";
    let public = "const k = process.env.NEXT_PUBLIC_API_SECRET;\n";
    std::fs::write(&app, [eval, public].concat()).unwrap();
    let (code, _, err) = scan(&["--write-baseline", baseline.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("Wrote 2 findings"), "{err}");
    let written = std::fs::read_to_string(&baseline).unwrap();
    assert!(
        !written.contains("eval(req") && !written.contains("NEXT_PUBLIC"),
        "{written}"
    );

    // The baseline sits in the scanned folder and gives no finding of its own.
    let (code, out, _) = scan(&["--json"]);
    assert_eq!(code, 1);
    assert_eq!(found(&out).len(), 2, "{out}");

    let with_baseline = ["--json", "--baseline", baseline.to_str().unwrap()];
    let (code, out, err) = scan(&with_baseline);
    assert_eq!((code, found(&out)), (0, vec![]), "{out}");
    assert!(err.contains("2 findings are in the baseline"), "{err}");

    // Moved code is still known; a new finding and a second copy of a known line are not.
    std::fs::write(&app, ["\n\n", public, eval].concat()).unwrap();
    assert_eq!(scan(&with_baseline).0, 0);
    let new = "const g = eval(req.query.x);\n";
    std::fs::write(&app, [eval, public, new, eval].concat()).unwrap();
    let (code, out, err) = scan(&with_baseline);
    assert_eq!(code, 1);
    let eval_at = |line| ("app.js".to_string(), "code.eval".to_string(), line);
    assert_eq!(found(&out), vec![eval_at(3), eval_at(4)], "{out}");
    assert!(err.contains("2 findings are in the baseline"), "{err}");

    // Only the --write-baseline format is read: a --json report is refused.
    let (_, report, _) = scan(&["--json"]);
    std::fs::write(&baseline, report).unwrap();
    assert_eq!(scan(&with_baseline).0, 2);
    std::fs::write(&baseline, "{\"findings\": []}").unwrap();
    assert_eq!(scan(&with_baseline).0, 2);
    std::fs::remove_file(&baseline).unwrap();
    assert_eq!(scan(&with_baseline).0, 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn baseline_file_holds_no_line_text() {
    let file = std::env::temp_dir().join(format!(
        "safe-anything-baseline-text-{}.json",
        std::process::id()
    ));
    for name in ["secrets", "config", "agent", "code"] {
        let (_, out) = run(&[&fixture(name), "--offline", "--json"]);
        let report: serde_json::Value = serde_json::from_str(&out).unwrap();
        let (code, _) = run(&[
            &fixture(name),
            "--offline",
            "--include-tests",
            "--write-baseline",
            file.to_str().unwrap(),
        ]);
        assert_eq!(code, 0);
        let written = std::fs::read_to_string(&file).unwrap();
        for f in report["findings"].as_array().unwrap() {
            let snippet = f["snippet"].as_str().unwrap();
            assert!(
                snippet.len() < 8 || !written.contains(snippet),
                "{name}: {snippet}"
            );
        }
        for word in ["snippet", "message", "line", "fix"] {
            assert!(!written.contains(&format!("\"{word}\"")), "{name}: {word}");
        }
        for value in [
            common::fake("password"),
            common::fake("db-password"),
            common::fake("github"),
            "supersecret123".to_string(),
        ] {
            assert!(!written.contains(&value), "{name}: {value}");
        }
    }
    std::fs::remove_file(&file).unwrap();
}

#[test]
fn mcp_server_scans_over_stdio() {
    use std::io::{BufRead, BufReader, Write};
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut ask = |msg: serde_json::Value| -> serde_json::Value {
        writeln!(stdin, "{msg}").unwrap();
        serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap()
    };
    let init = ask(
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "safe-anything");
    let tools = ask(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"scan") && names.contains(&"list_rules"),
        "{names:?}"
    );
    let call = ask(
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "scan", "arguments": {"path": fixture("agent"), "offline": true}}}),
    );
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    let report: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"] == "agent.mcp-unpinned")
    );
    drop(stdin);
    child.wait().unwrap();
}

#[test]
fn secrets_are_redacted_in_every_output() {
    let token = common::fake("github");
    let token_tail = &token[token.len() - 16..];
    let password = common::fake("password");
    let aws = common::fake("aws");
    let key_json = common::fake("private-key-json");
    let key_parts: Vec<&str> = key_json
        .split("\\n")
        .filter(|part| !part.contains("PRIVATE KEY") && !part.is_empty())
        .collect();
    assert_eq!(key_parts.len(), 3);
    for args in [
        vec![fixture("agent"), "--offline".into()],
        vec![fixture("agent"), "--offline".into(), "--json".into()],
        vec![fixture("secrets"), "--offline".into(), "--sarif".into()],
        vec![fixture("secrets"), "--offline".into()],
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (_, out) = run(&args);
        assert!(!out.contains(token_tail), "token leaked with {args:?}");
        assert!(!out.contains(&password), "password leaked with {args:?}");
        assert!(!out.contains(&aws[4..]), "AWS key leaked with {args:?}");
        for part in &key_parts {
            assert!(
                !out.contains(&part[4..]),
                "private key leaked with {args:?}"
            );
        }
    }
    let (_, out) = run(&[&fixture("agent"), "--offline"]);
    assert!(
        out.contains("\"GITHUB_TOKEN\": \"ghp_"),
        "only the value is masked:\n{out}"
    );
}

#[test]
fn public_env_secret_value_is_redacted() {
    // `secret.public-env-secret` matches the variable name; the value given to it must not be
    // printed either, in any output.
    let value = common::fake("db-password");
    let dir = std::env::temp_dir().join(format!("safe-anything-public-env-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Short values are joined from parts too, so the source holds no assignment that reads as a
    // real password.
    let (pin, pin2, first) = (
        ["zq", "7Kx"].concat(),
        ["Qv", "7k"].concat(),
        ["Jq", "9xW"].concat(),
    );
    let (qm, quoted, colon) = (
        ["?W", "z8k"].concat(),
        ["Hk", "4w"].concat(),
        ["Lm", "2z"].concat(),
    );
    // One finding per line; every way of giving the name a value must hide that value.
    let lines = [
        format!("export NEXT_PUBLIC_STRIPE_SECRET_KEY=\"{value}\""),
        format!("VITE_ADMIN_PASSWORD={value}"),
        format!("NUXT_PUBLIC_SMTP_PASSWORD = \"{value} and more\""),
        format!("GATSBY_API_SECRET=pa,ss;{value}"),
        format!("PUBLIC_PIN_PASSWORD={pin}"),
        // A short value with a comment after it, a second name, a one-letter value.
        format!("VITE_PIN_PASSWORD={pin2} # dev pin"),
        format!("VITE_A_SECRET={first}; VITE_B_SECRET={value}"),
        "echo NEXT_PUBLIC_ECHO_SECRET e".to_string(),
        // Values that start with, or are made of, operator and bracket characters.
        format!("VITE_QM_PASSWORD=\"{qm}\""),
        "VITE_EQS_PASSWORD=\"====\"".to_string(),
        "VITE_PUN_PASSWORD=\":;,\"".to_string(),
        "VITE_BARE_PASSWORD=;,)]}".to_string(),
        format!("ENV NEXT_PUBLIC_QUOTED_SECRET \":= '{quoted}'\""),
        format!("VITE_COLON_PASSWORD:={colon}"),
        format!("const NEXT_PUBLIC_API_SECRET: string = \"{value}\";"),
        format!("$cfg = ['VITE_HASH_PASSWORD' => '{value}'];"),
        format!("const k = process.env.VITE_FALLBACK_SECRET || \"{value}\";"),
        format!("process.env[\"REACT_APP_IDX_SECRET\"] = \"{value}\";"),
        format!("ENV NEXT_PUBLIC_DOCKER_SECRET {value}"),
        format!("{{\"VITE_A_SECRET\": \"{first}\", \"VITE_B_SECRET\": \"{value}\"}}"),
        format!("if (NEXT_PUBLIC_CMP_SECRET === \"{value}\") {{}}"),
        format!("REACT_APP_DB_PASSWORD: '{value}'"),
        format!("{{\"EXPO_PUBLIC_SERVICE_ROLE\": \"{value}\"}}"),
        // Nothing after the name but punctuation: printed as is, still reported.
        "const key = process.env.NEXT_PUBLIC_OPENAI_KEY;".to_string(),
        "NEXT_PUBLIC_EMPTY_SECRET=".to_string(),
    ];
    std::fs::write(dir.join("vars.sh"), lines.join("\n") + "\n").unwrap();
    let path = dir.to_string_lossy().into_owned();
    for extra in [None, Some("--json"), Some("--sarif")] {
        let mut args = vec![path.as_str(), "--offline"];
        args.extend(extra);
        let (_, out) = run(&args);
        assert!(!out.contains(&value), "value leaked with {args:?}:\n{out}");
        for part in [
            "and more", "pa,ss", "zq7Kx", "Qv7k", "Jq9x", "?Wz8", "\"====", ":;,", ";,)]}", "Hk4w",
            "Lm2z", ":= '",
        ] {
            assert!(!out.contains(part), "{part:?} leaked with {args:?}:\n{out}");
        }
        assert!(
            out.matches("secret.public-env-secret").count() >= lines.len(),
            "findings missing with {args:?}:\n{out}"
        );
    }
    let (_, out) = run(&[&path, "--offline"]);
    for kept in [
        "VITE_ADMIN_PASSWORD****\n",
        "echo NEXT_PUBLIC_ECHO_SECRET ****\n",
        "ENV NEXT_PUBLIC_DOCKER_SECRET ****\n",
        "process.env.NEXT_PUBLIC_OPENAI_KEY;",
        "NEXT_PUBLIC_EMPTY_SECRET=\n",
    ] {
        assert!(
            out.contains(kept),
            "{kept:?} expected in the output:\n{out}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn help_shows_mcp_and_how_to_ignore() {
    let (code, out) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("safe-anything mcp"), "{out}");
    assert!(out.contains("safe-anything:ignore"), "{out}");
    assert!(out.contains(".safe-anything-ignore"), "{out}");
}
