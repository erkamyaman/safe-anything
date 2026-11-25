use super::{FileInfo, Rule};
use crate::{Family, Severity};

fn js(f: &FileInfo) -> bool {
    f.ext_in(&[
        "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "html", "htm", "astro",
    ])
}
fn py(f: &FileInfo) -> bool {
    f.ext == "py"
}
fn go(f: &FileInfo) -> bool {
    f.ext == "go"
}
fn jvm(f: &FileInfo) -> bool {
    f.ext_in(&["java", "kt", "scala", "groovy"])
}
fn php(f: &FileInfo) -> bool {
    f.ext_in(&["php", "phtml"])
}
fn rb(f: &FileInfo) -> bool {
    f.ext_in(&["rb", "erb", "haml"])
}
fn cs(f: &FileInfo) -> bool {
    f.ext_in(&["cs", "cshtml", "razor"])
}
fn sql(f: &FileInfo) -> bool {
    f.ext == "sql"
}
fn vue_svelte(f: &FileInfo) -> bool {
    f.ext_in(&["vue", "svelte", "html", "htm"])
}
fn django_settings(f: &FileInfo) -> bool {
    f.name == "settings.py"
}
fn code(f: &FileInfo) -> bool {
    js(f) || py(f) || go(f) || jvm(f) || php(f) || rb(f) || cs(f)
}
fn js_py(f: &FileInfo) -> bool {
    js(f) || py(f)
}

macro_rules! kw {
    () => {
        r"(?i:select\s.+?\sfrom\b|insert\s+into\b|update\s+\w+\s+set\b|delete\s+from\b)"
    };
}

macro_rules! rule {
    ($id:literal, $sev:ident, $files:ident, $pat:expr, $unless:expr, $msg:expr, $fix:expr) => {
        Rule {
            id: $id,
            family: Family::Code,
            severity: Severity::$sev,
            files: $files,
            pattern: $pat,
            unless: $unless,
            message: $msg,
            fix: $fix,
        }
    };
}

const SQLI_MSG: &str = "A SQL query is built from variables by string formatting, so input can change the query (SQL injection).";
const SQLI_FIX: &str = "Use parameterized queries (placeholders like ?, $1 or %s passed separately) or the ORM's query builder.";
const CMD_MSG: &str =
    "A shell command is built from variables, so input can run other commands (command injection).";
const CMD_FIX: &str = "Call the program directly with an argument list (no shell), and validate the input against an allow list.";
const DESER_MSG: &str =
    "Untrusted data is deserialized with a format that can run code or build arbitrary objects.";
const DESER_FIX: &str = "Use a data-only format such as JSON, or a safe loader, and never deserialize input from users or the network.";

pub static RULES: &[Rule] = &[
    rule!(
        "code.xss-inner-html",
        Medium,
        js,
        r"\.(?:inner|outer)HTML\s*\+?=[^=]",
        Some(r#"(?:inner|outer)HTML\s*\+?=\s*(?:''|""|``|'[^'$+]*'\s*;?\s*$|"[^"$+]*"\s*;?\s*$)"#),
        "HTML is written from a variable; if it holds user input, scripts run in the page (XSS).",
        "Use textContent for text, or sanitize the HTML with a library such as DOMPurify first."
    ),
    rule!(
        "code.xss-document-write",
        Medium,
        js,
        r"\bdocument\.write(?:ln)?\s*\(",
        None,
        "document.write puts raw HTML into the page; with user input this is XSS.",
        "Build elements with the DOM API and set textContent instead."
    ),
    rule!(
        "code.xss-dangerously-set-inner-html",
        Medium,
        js,
        r"dangerouslySetInnerHTML\s*=",
        Some(r"(?i)purify|sanitize"),
        "dangerouslySetInnerHTML renders raw HTML; with user content this is XSS.",
        "Render the text as children, or sanitize the HTML (DOMPurify) right where it is set."
    ),
    rule!(
        "code.xss-v-html",
        Medium,
        vue_svelte,
        r#"\bv-html\s*=|\{@html\s"#,
        Some(r"(?i)purify|sanitize"),
        "Raw HTML is rendered from a variable; with user content this is XSS.",
        "Use text interpolation, or sanitize the HTML before rendering it."
    ),
    rule!(
        "code.xss-reflected",
        Medium,
        php,
        r"\b(?:echo|print)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        None,
        "Request input is printed into the page without escaping (reflected XSS).",
        "Escape output with htmlspecialchars($value, ENT_QUOTES, 'UTF-8')."
    ),
    rule!(
        "code.xss-raw-html",
        Medium,
        rb,
        r"\braw\s*\(?\s*@|\.html_safe\b",
        None,
        "A value is marked as safe HTML, so Rails will not escape it (XSS if it holds user input).",
        "Let Rails escape it, or sanitize it with the sanitize helper."
    ),
    rule!(
        "code.eval",
        High,
        code,
        r"(?m)(?:^|[^\w.$\n])eval\s*\(|\bnew\s+Function\s*\(",
        Some(r#"new\s+Function\s*\(\s*(?:(?:'[^']*'|"[^"]*")\s*,?\s*)+\)"#),
        "Code is evaluated from a string at run time; if any part comes from input, an attacker can run code.",
        "Remove eval. Parse data with JSON.parse / json.loads, or map allowed inputs to functions."
    ),
    rule!(
        "code.command-injection",
        High,
        js,
        r#"(?m)(?:^|[^.\w\n]|\b(?:child_process|childProcess|cp)\.)(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)"#,
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.command-injection",
        High,
        py,
        r#"\bshell\s*=\s*True|\bos\.(?:system|popen)\s*\(\s*(?:f["']|[A-Za-z_]|["'][^"']*["']\s*[+%])"#,
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.command-injection",
        High,
        go,
        r#"exec\.Command(?:Context)?\((?:\s*\w+\s*,)?\s*"(?:sh|bash|/bin/sh|/bin/bash|cmd|cmd\.exe)"\s*,\s*"(?:-c|/c|/C)""#,
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.command-injection",
        High,
        jvm,
        r#"Runtime\.getRuntime\(\)\.exec\(\s*(?:"[^"]*"\s*\+|[a-z_]\w*\s*\))"#,
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.command-injection",
        Critical,
        php,
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.command-injection",
        High,
        php,
        r#"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(?:['"][^'"]*['"]\s*\.\s*\$|"[^"]*\$[A-Za-z_{])"#,
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.command-injection",
        High,
        rb,
        r#"\b(?:system|exec|spawn)\s*\(?\s*"[^"]*#\{|`[^`]*#\{|%x\([^)]*#\{"#,
        None,
        CMD_MSG,
        CMD_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        js,
        concat!(
            r#"`\s*"#,
            kw!(),
            r#"[^`]*\$\{|["']\s*"#,
            kw!(),
            r#"[^"']*["']\s*\+\s*[A-Za-z_$]"#
        ),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        py,
        concat!(
            r#"\bf"\s*"#,
            kw!(),
            r#"[^"]*\{|\bf'\s*"#,
            kw!(),
            r#"[^']*\{|"\s*"#,
            kw!(),
            r#"[^"]*"\s*(?:%\s*[\w(]|\+\s*[A-Za-z_]|\.format\()|'\s*"#,
            kw!(),
            r#"[^']*'\s*(?:%\s*[\w(]|\+\s*[A-Za-z_]|\.format\()"#
        ),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        go,
        r#"fmt\.Sprintf\(\s*"(?i:select|insert|update|delete)[^"]*%[sdvq]"#,
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        go,
        concat!(
            r#"\.(?:Query|QueryRow|Exec)(?:\(|Context\(\s*[\w.]+(?:\(\))?\s*,)\s*(?:"\s*"#,
            kw!(),
            r#"[^"]*"|`\s*"#,
            kw!(),
            r#"[^`]*`)\s*\+\s*[A-Za-z_]"#
        ),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        jvm,
        concat!(r#""\s*"#, kw!(), r#"[^"]*"\s*\+\s*[A-Za-z_]"#),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        php,
        concat!(
            r#"["']\s*"#,
            kw!(),
            r#"[^"']*["']\s*\.\s*\$|"\s*"#,
            kw!(),
            r#"[^"]*\$[A-Za-z_{]"#
        ),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        rb,
        concat!(
            r#"\.(?:where|find_by_sql|order|group|having|joins|select|pluck|exists\?)\(\s*"[^"]*#\{|"\s*"#,
            kw!(),
            r#"[^"]*#\{"#
        ),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.sql-injection",
        High,
        cs,
        concat!(
            r#""\s*"#,
            kw!(),
            r#"[^"]*"\s*\+\s*[A-Za-z_]|\$@?"\s*"#,
            kw!(),
            r#"[^"]*\{"#
        ),
        None,
        SQLI_MSG,
        SQLI_FIX
    ),
    rule!(
        "code.path-traversal",
        High,
        js,
        r"\b(?:sendFile|readFile|readFileSync|createReadStream|download|unlink|unlinkSync)\s*\(\s*req\.(?:query|params|body)",
        Some(r"\broot\s*:"),
        "A file path comes straight from the request, so ../ can reach any file on the server (path traversal).",
        "Resolve the path against a fixed base directory and reject results outside it, or map ids to known files."
    ),
    rule!(
        "code.path-traversal",
        High,
        py,
        r"\b(?:open|send_file|send_from_directory)\s*\(\s*request\.(?:args|form|values|GET|POST|files|json)",
        None,
        "A file path comes straight from the request, so ../ can reach any file on the server (path traversal).",
        "Resolve the path against a fixed base directory and reject results outside it, or map ids to known files."
    ),
    rule!(
        "code.ssrf",
        High,
        js,
        r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|needle|http\.get|https\.get|request)\s*\(\s*req\.(?:query|params|body)",
        None,
        "The server fetches a URL taken from the request, so users can reach internal services (SSRF).",
        "Allow only known hosts, block private and link-local addresses, and never pass the raw URL through."
    ),
    rule!(
        "code.ssrf",
        High,
        py,
        r"\b(?:requests\.(?:get|post|put|head|request)|urlopen|httpx\.(?:get|post))\s*\(\s*request\.(?:args|form|values|GET|POST|json)",
        None,
        "The server fetches a URL taken from the request, so users can reach internal services (SSRF).",
        "Allow only known hosts, block private and link-local addresses, and never pass the raw URL through."
    ),
    rule!(
        "code.ssrf",
        High,
        go,
        r"\bhttp\.(?:Get|Head|Post)\(\s*(?:r|req)\.(?:FormValue\(|URL\.Query\(\)\.Get\()",
        None,
        "The server fetches a URL taken from the request, so users can reach internal services (SSRF).",
        "Allow only known hosts, block private and link-local addresses, and never pass the raw URL through."
    ),
    rule!(
        "code.ssrf",
        High,
        php,
        r"\b(?:file_get_contents|curl_init|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST)\b",
        None,
        "The server fetches a URL taken from the request, so users can reach internal services (SSRF).",
        "Allow only known hosts, block private and link-local addresses, and never pass the raw URL through."
    ),
    rule!(
        "code.open-redirect",
        Medium,
        js,
        r"\b(?:res|response|reply)\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?req\.(?:query|params|body)",
        None,
        "The redirect target is taken from the request, so a crafted link can send users to any site from your domain (open redirect).",
        "Redirect only to a fixed path or a URL on an allow list; never pass request input straight to redirect."
    ),
    rule!(
        "code.open-redirect",
        Medium,
        py,
        r"\bredirect\s*\(\s*request\.(?:args|form|values|GET|POST|query_params)",
        None,
        "The redirect target is taken from the request, so a crafted link can send users to any site from your domain (open redirect).",
        "Redirect only to a fixed path or a URL on an allow list; never pass request input straight to redirect."
    ),
    rule!(
        "code.tls-verify-off",
        Medium,
        code,
        r#"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|ServerCertificateValidationCallback\s*=[^;]*=>\s*true"#,
        None,
        "TLS certificate checks are turned off, so anyone on the network can read or change the traffic.",
        "Keep verification on; for a private CA, pass its certificate (ca / verify=path) instead of disabling checks."
    ),
    rule!(
        "code.weak-hash",
        Low,
        code,
        r#"createHash\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\(|\b(?:md5|sha1)\.New\(\)|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"|\b(?:md5|sha1)\s*\(\s*\$\w*(?:pass|pwd)"#,
        None,
        "MD5 and SHA-1 are broken for security use (collisions; too fast for passwords).",
        "Use SHA-256 or better for integrity, and bcrypt, scrypt or Argon2 for passwords. Ignore if this is a non-security checksum."
    ),
    rule!(
        "code.weak-cipher",
        Medium,
        code,
        r#"Cipher\.getInstance\(\s*"(?:DES|RC4|DESede|[^"]*/ECB/)|\bDES\.new\(|\bARC4\.new\(|\bMODE_ECB\b|createCipheriv\(\s*['"](?:des|rc4|aes-\d+-ecb)"#,
        None,
        "A weak cipher or ECB mode is used; ECB leaks patterns and DES/RC4 are broken.",
        "Use AES-GCM or ChaCha20-Poly1305 with a random nonce."
    ),
    rule!(
        "code.insecure-cookie",
        Low,
        js_py,
        r"\b(?:httpOnly|httponly|secure)\s*[:=]\s*(?:false|False)\b",
        None,
        "A cookie is set without HttpOnly or Secure, so scripts or plain HTTP can read it.",
        "Set httpOnly: true and secure: true (and sameSite) on session cookies."
    ),
    rule!(
        "code.jwt-none",
        High,
        js_py,
        r#"algorithms\s*[:=]\s*\[\s*['"]none['"]|['"]verify_signature['"]\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False"#,
        None,
        "JWT signatures are not checked, so anyone can forge a token.",
        "Verify tokens with a fixed list of real algorithms (e.g. RS256 or HS256) and the right key."
    ),
    rule!(
        "code.cors-wildcard",
        Low,
        code,
        r#"Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]"#,
        None,
        "CORS allows every origin. Fine for public data; risky for anything behind a login.",
        "List the origins that may call the API instead of *."
    ),
    rule!(
        "code.insecure-random",
        Medium,
        js_py,
        r"(?i)(?:token|secret|password|nonce|salt|session|otp|api_?key)\w*\s*[:=][^\n]*(?:Math\.random\(\)|random\.(?:random|randint|choice)\()",
        None,
        "A secret value is made with a non-cryptographic random generator, which can be predicted.",
        "Use crypto.randomUUID() / crypto.getRandomValues() in JS, or the secrets module in Python."
    ),
    rule!(
        "code.debug-enabled",
        Medium,
        py,
        r"\.run\([^)]*\bdebug\s*=\s*True",
        None,
        "The app runs in debug mode; the debugger can run code and leaks internals.",
        "Turn debug off outside local development (read it from the environment)."
    ),
    rule!(
        "code.debug-enabled",
        Medium,
        django_settings,
        r"(?m)^\s*DEBUG\s*=\s*True\b",
        None,
        "Django DEBUG is on; error pages leak settings and code.",
        "Set DEBUG from the environment and keep it False in production."
    ),
    rule!(
        "code.template-injection",
        High,
        py,
        r"\brender_template_string\s*\(\s*request\.|\bTemplate\s*\(\s*request\.",
        None,
        "A template is built from request input, so users can run code in the template engine (SSTI).",
        "Render fixed template files and pass user input only as variables."
    ),
    // Split from yaml.load/load_all below: `unless` is matched against the
    // whole line, so a SafeLoader call on the same line would otherwise hide
    // an unsafe call (e.g. `yaml.unsafe_load(x); yaml.load(y,
    // Loader=yaml.SafeLoader)`). These calls have no safe-loader form, so
    // they need no exception.
    rule!(
        "code.unsafe-deserialization",
        High,
        py,
        r"\bpickle\.loads?\s*\(|\byaml\.unsafe_load\s*\(|\bmarshal\.loads?\s*\(",
        None,
        DESER_MSG,
        DESER_FIX
    ),
    rule!(
        "code.unsafe-deserialization",
        High,
        py,
        r"\byaml\.load\s*\(|\byaml\.load_all\s*\(",
        Some(r"Loader\s*=\s*(?:yaml\.)?C?SafeLoader"),
        DESER_MSG,
        DESER_FIX
    ),
    rule!(
        "code.unsafe-deserialization",
        High,
        jvm,
        r"\bnew\s+ObjectInputStream\s*\(|\bXMLDecoder\s*\(",
        None,
        DESER_MSG,
        DESER_FIX
    ),
    rule!(
        "code.unsafe-deserialization",
        Critical,
        php,
        r"\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        None,
        DESER_MSG,
        DESER_FIX
    ),
    rule!(
        "code.unsafe-deserialization",
        High,
        rb,
        r"\bMarshal\.load\s*\(|\bMarshal\.restore\s*\(|\bYAML\.load\s*\(|\bYAML\.unsafe_load\s*\(",
        // No safe_load exception: the pattern never matches YAML.safe_load,
        // so keeping it here only let a safe call on the same line hide an
        // unsafe one. permitted_classes stays: YAML.load with an allow list
        // is the safe form.
        Some(r"permitted_classes"),
        DESER_MSG,
        DESER_FIX
    ),
    rule!(
        "code.unsafe-deserialization",
        High,
        cs,
        r"\bBinaryFormatter\b|\bNetDataContractSerializer\b|TypeNameHandling\.(?:All|Auto|Objects)",
        None,
        DESER_MSG,
        DESER_FIX
    ),
    rule!(
        "code.file-inclusion",
        Critical,
        php,
        r"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
        None,
        "A file to include comes from the request, so attackers can load other files or remote code.",
        "Map allowed page names to fixed files instead of including request input."
    ),
    rule!(
        "code.sql-grant-all",
        Medium,
        sql,
        r"(?i)\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+\*\.\*",
        None,
        "A database user gets every privilege on every database.",
        "Grant only the privileges the app needs on its own database."
    ),
    rule!(
        "code.sql-plaintext-password",
        Medium,
        sql,
        r"(?i)\bIDENTIFIED\s+BY\s+'[^']+'|\bWITH\s+PASSWORD\s+'[^']+'|\bCREATE\s+(?:USER|ROLE)\b[^;]*\bPASSWORD\s+'[^']+'",
        None,
        "A database password is written in a SQL file.",
        "Create users with passwords passed in at deploy time, not stored in migrations."
    ),
];
