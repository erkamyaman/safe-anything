pub struct Refs {
    pub cwe: &'static str,
    pub owasp: &'static str,
    pub learn_more: &'static str,
}

macro_rules! r {
    ($cwe:literal, $owasp:literal, $sheet:literal) => {
        Refs {
            cwe: $cwe,
            owasp: $owasp,
            learn_more: concat!(
                "https://cheatsheetseries.owasp.org/cheatsheets/",
                $sheet,
                ".html"
            ),
        }
    };
    ($cwe:literal, $owasp:literal, url $url:literal) => {
        Refs {
            cwe: $cwe,
            owasp: $owasp,
            learn_more: $url,
        }
    };
}

pub fn of(id: &str) -> Refs {
    match id {
        "code.xss-inner-html"
        | "code.xss-document-write"
        | "code.xss-dangerously-set-inner-html"
        | "code.xss-v-html"
        | "code.xss-reflected"
        | "code.xss-raw-html" => {
            r!(
                "CWE-79",
                "A03:2021 Injection",
                "Cross_Site_Scripting_Prevention_Cheat_Sheet"
            )
        }
        "code.eval" => r!(
            "CWE-95",
            "A03:2021 Injection",
            "Injection_Prevention_Cheat_Sheet"
        ),
        "code.command-injection" => r!(
            "CWE-78",
            "A03:2021 Injection",
            "OS_Command_Injection_Defense_Cheat_Sheet"
        ),
        "code.sql-injection" => r!(
            "CWE-89",
            "A03:2021 Injection",
            "SQL_Injection_Prevention_Cheat_Sheet"
        ),
        "code.path-traversal" | "code.file-inclusion" => r!(
            "CWE-22",
            "A01:2021 Broken Access Control",
            "File_Upload_Cheat_Sheet"
        ),
        "code.ssrf" => r!(
            "CWE-918",
            "A10:2021 Server-Side Request Forgery",
            "Server_Side_Request_Forgery_Prevention_Cheat_Sheet"
        ),
        "code.open-redirect" => r!(
            "CWE-601",
            "A01:2021 Broken Access Control",
            "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
        ),
        "code.tls-verify-off" => r!(
            "CWE-295",
            "A02:2021 Cryptographic Failures",
            "Transport_Layer_Security_Cheat_Sheet"
        ),
        "code.weak-hash" => r!(
            "CWE-328",
            "A02:2021 Cryptographic Failures",
            "Password_Storage_Cheat_Sheet"
        ),
        "code.weak-cipher" => r!(
            "CWE-327",
            "A02:2021 Cryptographic Failures",
            "Cryptographic_Storage_Cheat_Sheet"
        ),
        "code.insecure-cookie" => r!(
            "CWE-614",
            "A05:2021 Security Misconfiguration",
            "Session_Management_Cheat_Sheet"
        ),
        "code.jwt-none" => r!(
            "CWE-347",
            "A07:2021 Identification and Authentication Failures",
            "JSON_Web_Token_Cheat_Sheet"
        ),
        "code.cors-wildcard" => r!(
            "CWE-942",
            "A05:2021 Security Misconfiguration",
            "HTML5_Security_Cheat_Sheet"
        ),
        "code.insecure-random" => r!(
            "CWE-338",
            "A02:2021 Cryptographic Failures",
            "Cryptographic_Storage_Cheat_Sheet"
        ),
        "code.debug-enabled" => r!(
            "CWE-489",
            "A05:2021 Security Misconfiguration",
            "Error_Handling_Cheat_Sheet"
        ),
        "code.template-injection" => r!(
            "CWE-1336",
            "A03:2021 Injection",
            "Injection_Prevention_Cheat_Sheet"
        ),
        "code.unsafe-deserialization" => r!(
            "CWE-502",
            "A08:2021 Software and Data Integrity Failures",
            "Deserialization_Cheat_Sheet"
        ),
        "code.sql-grant-all" => r!(
            "CWE-250",
            "A01:2021 Broken Access Control",
            "Database_Security_Cheat_Sheet"
        ),
        "code.sql-plaintext-password" => r!(
            "CWE-798",
            "A07:2021 Identification and Authentication Failures",
            "Database_Security_Cheat_Sheet"
        ),
        "secret.env-file" | "secret.hardcoded-password" | "secret.url-credentials" => {
            r!(
                "CWE-798",
                "A07:2021 Identification and Authentication Failures",
                "Secrets_Management_Cheat_Sheet"
            )
        }
        "secret.public-env-secret" => r!(
            "CWE-200",
            "A05:2021 Security Misconfiguration",
            "Secrets_Management_Cheat_Sheet"
        ),
        "secret.env-not-ignored" => r!(
            "CWE-538",
            "A05:2021 Security Misconfiguration",
            "Secrets_Management_Cheat_Sheet"
        ),
        "secret.private-key" => r!(
            "CWE-321",
            "A02:2021 Cryptographic Failures",
            "Key_Management_Cheat_Sheet"
        ),
        s if s.starts_with("secret.") => r!(
            "CWE-798",
            "A07:2021 Identification and Authentication Failures",
            "Secrets_Management_Cheat_Sheet"
        ),
        "agent.bypass-permissions" | "agent.unrestricted-shell" => {
            r!("CWE-250", "LLM06:2025 Excessive Agency", url "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/")
        }
        "agent.mcp-auto-approve" => {
            r!("CWE-829", "LLM06:2025 Excessive Agency", url "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/")
        }
        "agent.remote-script" => {
            r!("CWE-494", "LLM03:2025 Supply Chain", url "https://genai.owasp.org/llmrisk/llm032025-supply-chain/")
        }
        "agent.mcp-unpinned" => {
            r!("CWE-1357", "LLM03:2025 Supply Chain", url "https://genai.owasp.org/llmrisk/llm032025-supply-chain/")
        }
        "agent.prompt-injection" | "agent.hidden-unicode" => {
            r!("CWE-1427", "LLM01:2025 Prompt Injection", url "https://genai.owasp.org/llmrisk/llm01-prompt-injection/")
        }
        "agent.sensitive-file-access" => {
            r!("CWE-200", "LLM02:2025 Sensitive Information Disclosure", url "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/")
        }
        "agent.mcp-plaintext-secret" => r!(
            "CWE-798",
            "LLM02:2025 Sensitive Information Disclosure",
            "Secrets_Management_Cheat_Sheet"
        ),
        "agent.mcp-insecure-url" => r!(
            "CWE-319",
            "A02:2021 Cryptographic Failures",
            "Transport_Layer_Security_Cheat_Sheet"
        ),
        "mobile.android-debuggable" => {
            r!("CWE-489", "MASVS-RESILIENCE", url "https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/")
        }
        "mobile.android-allow-backup" | "mobile.insecure-storage" | "mobile.world-readable" => {
            r!("CWE-922", "MASVS-STORAGE", url "https://mas.owasp.org/MASVS/05-MASVS-STORAGE/")
        }
        "mobile.android-cleartext" | "mobile.ios-ats-disabled" => {
            r!("CWE-319", "MASVS-NETWORK", url "https://mas.owasp.org/MASVS/08-MASVS-NETWORK/")
        }
        "mobile.android-exported-provider" => {
            r!("CWE-926", "MASVS-PLATFORM", url "https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/")
        }
        "mobile.webview-js-bridge" | "mobile.webview-file-access" => {
            r!("CWE-749", "MASVS-PLATFORM", url "https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/")
        }
        "config.remote-script" | "config.docker-add-url" => r!(
            "CWE-494",
            "A08:2021 Software and Data Integrity Failures",
            "Software_Supply_Chain_Security_Cheat_Sheet"
        ),
        "config.docker-unpinned-image" => r!(
            "CWE-1357",
            "A06:2021 Vulnerable and Outdated Components",
            "Docker_Security_Cheat_Sheet"
        ),
        "config.docker-secret-env" => r!(
            "CWE-798",
            "A05:2021 Security Misconfiguration",
            "Docker_Security_Cheat_Sheet"
        ),
        "config.docker-root-user" | "config.privileged-container" | "config.k8s-host-access" => {
            r!(
                "CWE-250",
                "A05:2021 Security Misconfiguration",
                "Kubernetes_Security_Cheat_Sheet"
            )
        }
        "config.gha-pull-request-target"
        | "config.gha-write-all"
        | "config.gha-unpinned-action" => {
            r!(
                "CWE-829",
                "A08:2021 Software and Data Integrity Failures",
                "CI_CD_Security_Cheat_Sheet"
            )
        }
        "config.gha-script-injection" => {
            r!("CWE-78", "A03:2021 Injection", "CI_CD_Security_Cheat_Sheet")
        }
        "config.tf-open-ingress"
        | "config.tf-public-bucket"
        | "config.tf-public-access-block"
        | "config.tf-public-database" => {
            r!(
                "CWE-284",
                "A01:2021 Broken Access Control",
                "Infrastructure_as_Code_Security_Cheat_Sheet"
            )
        }
        "config.tf-unencrypted-storage" => r!(
            "CWE-311",
            "A02:2021 Cryptographic Failures",
            "Cryptographic_Storage_Cheat_Sheet"
        ),
        "config.nginx-autoindex" => r!(
            "CWE-548",
            "A05:2021 Security Misconfiguration",
            "Attack_Surface_Analysis_Cheat_Sheet"
        ),
        "config.weak-tls-version" => r!(
            "CWE-326",
            "A02:2021 Cryptographic Failures",
            "Transport_Layer_Security_Cheat_Sheet"
        ),
        "dependency.known-vulnerability" => r!(
            "CWE-1395",
            "A06:2021 Vulnerable and Outdated Components",
            "Vulnerable_Dependency_Management_Cheat_Sheet"
        ),
        _ => r!("CWE-710", "", url "https://cwe.mitre.org/"),
    }
}
