//! SEC-001, SEC-002, SEC-003: secrets in the repo and secrets reaching the browser.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use regex::Regex;

use super::{Meta, is_code, is_env_example, is_env_file, is_noise, line_no, short};
use crate::mask::{mask, mask_in};
use crate::rule::{Rule, RuleInfo};
use crate::{Confidence, Finding, Project, Severity, SourceFile, Stack};

/// Known secret shapes: (what it is, pattern).
static TOKENS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        (
            "a live Stripe secret key",
            r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b",
        ),
        (
            "a Stripe webhook signing secret",
            r"\bwhsec_[0-9A-Za-z]{24,}\b",
        ),
        ("an AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
        (
            "a private key",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        ),
        (
            "an OpenAI or Anthropic API key",
            r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{32,}",
        ),
        (
            "a GitHub token",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}",
        ),
    ]
    .into_iter()
    .filter_map(|(what, re)| Regex::new(re).ok().map(|r| (what, r)))
    .collect()
});

static JWT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}").ok()
});

/// Assignment of a secret-sounding name in a dotenv file: `STRIPE_SECRET_KEY=...` with a value.
static SECRET_ASSIGNMENT: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|_KEY)[A-Z0-9_]*\s*=\s*\S").ok()
});

/// Client-exposed variable names: `NEXT_PUBLIC_…`, `VITE_…`, `EXPO_PUBLIC_…`, `REACT_APP_…`, `PUBLIC_…`.
static CLIENT_VAR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_)[A-Z0-9_]+\b").ok()
});

/// Whether a JWT's payload says `"role":"service_role"` (a Supabase admin key).
fn is_service_role_jwt(token: &str) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .is_some_and(|json| json.replace(' ', "").contains("\"role\":\"service_role\""))
}

/// Every secret on a line: (what it is, the matched text).
fn secrets_in(line: &str) -> Vec<(&'static str, String)> {
    let mut found: Vec<(&'static str, String)> = TOKENS
        .iter()
        .flat_map(|(what, re)| {
            re.find_iter(line)
                .map(move |m| (*what, m.as_str().to_owned()))
        })
        .collect();
    if let Some(jwt) = JWT.as_ref() {
        for m in jwt.find_iter(line) {
            if is_service_role_jwt(m.as_str()) {
                found.push(("a Supabase service-role key", m.as_str().to_owned()));
            }
        }
    }
    found
}

/// Mask every secret on a line and shorten it for display.
fn masked_line(line: &str, secrets: &[(&'static str, String)]) -> String {
    let mut out = line.to_owned();
    for (_, s) in secrets {
        if s.starts_with("-----BEGIN") {
            continue;
        }
        out = mask_in(&out, s);
    }
    short(&out)
}

// ---------------------------------------------------------------- SEC-001

/// SEC-001: secrets committed to the repo.
pub struct CommittedSecrets;

const SEC_001: Meta = Meta {
    id: "SEC-001",
    title: "Secret committed to the repo",
    severity: Severity::Critical,
    confidence: Confidence::High,
};

const SEC_001_INFO: RuleInfo = SEC_001.info(
    "Keys and secrets committed to the repo",
    "Live Stripe keys, webhook secrets, AWS keys, private keys, OpenAI/Anthropic and GitHub tokens or a Supabase service-role key written into the code, or a .env file with secret values that git does not ignore. Anyone who can read the repository, including everyone with access to a fork or a leaked copy, can use them. Revoke and replace the key first, then load it from an environment variable that is never committed.",
);

impl Rule for CommittedSecrets {
    fn info(&self) -> &'static RuleInfo {
        &SEC_001_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| is_code(f) && !is_noise(f)) {
            let Some(text) = file.text() else { continue };
            let example = is_env_example(file);
            let mut any_token = false;
            for (i, line) in text.lines().enumerate() {
                let secrets = secrets_in(line);
                if secrets.is_empty() || example {
                    continue;
                }
                any_token = true;
                let what = secrets[0].0;
                out.push(SEC_001.finding(
                    file,
                    line_no(i),
                    masked_line(line, &secrets),
                    format!("This is {what}. Anyone who can read the code can use it."),
                    "Revoke and replace it now, then load it from an environment variable that is not committed."
                        .to_owned(),
                ));
            }
            if is_env_file(file) && !example && !any_token && has_secret_assignment(text) {
                out.push(SEC_001.finding(
                    file,
                    None,
                    String::new(),
                    format!(
                        "`{}` holds secret values and is not ignored by git, so it ships with your code.",
                        file.name()
                    ),
                    format!(
                        "Add `{}` to `.gitignore`, run `git rm --cached {}`, and rotate the values it held.",
                        file.name(),
                        file.path
                    ),
                ));
            }
        }
        out
    }
}

fn has_secret_assignment(text: &str) -> bool {
    let Some(re) = SECRET_ASSIGNMENT.as_ref() else {
        return false;
    };
    text.lines()
        .any(|l| re.is_match(l) && !l.contains("NEXT_PUBLIC_") && !l.contains("VITE_"))
}

// ---------------------------------------------------------------- SEC-002

/// SEC-002: the Supabase service-role key used in code that runs in the browser.
pub struct ServiceRoleInBrowser;

const SEC_002: Meta = Meta {
    id: "SEC-002",
    title: "Supabase service-role key in browser code",
    severity: Severity::Critical,
    confidence: Confidence::High,
};

/// Whether a source file ends up in the browser bundle.
pub(crate) fn runs_in_browser(file: &SourceFile, project: &Project) -> bool {
    let p = file.path.as_str();
    let name = file.name();
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if !["js", "jsx", "ts", "tsx", "mjs", "svelte", "vue", "astro"].contains(&ext) {
        return false;
    }
    let server_path = p.contains("/api/")
        || p.starts_with("api/")
        || p.contains("/server/")
        || p.starts_with("server/")
        || name.contains(".server.")
        || p.contains("supabase/functions/")
        || p.contains("/functions/")
        || name.starts_with("middleware.")
        || name.starts_with("route.");
    if server_path {
        return false;
    }
    if matches!(ext, "svelte" | "vue") {
        return true;
    }
    let use_client = file.text().is_some_and(|t| {
        t.lines().take(5).any(|l| {
            matches!(
                l.trim().trim_end_matches(';'),
                "'use client'" | "\"use client\""
            )
        })
    });
    if use_client {
        return true;
    }
    let seg = |s: &str| p.starts_with(s) || p.contains(&format!("/{s}"));
    if seg("components/") || seg("hooks/") || (seg("pages/") && !p.contains("pages/api/")) {
        return true;
    }
    project.uses(Stack::Vite) && !project.uses(Stack::NextJs) && seg("src/")
}

const SEC_002_INFO: RuleInfo = SEC_002.info(
    "The Supabase service-role key used in browser code",
    "The service-role key bypasses every Row Level Security rule. When it is used in a client component, a components/ file or a Vite src/ file, it is shipped to every visitor, who can then read and change all data. Use the anon key in the browser and keep the service-role key in server routes, edge functions or server-only files.",
);

impl Rule for ServiceRoleInBrowser {
    fn info(&self) -> &'static RuleInfo {
        &SEC_002_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| runs_in_browser(f, project)) {
            let Some(text) = file.text() else { continue };
            for (i, line) in text.lines().enumerate() {
                let jwt = JWT
                    .as_ref()
                    .and_then(|re| re.find(line))
                    .map(|m| m.as_str().to_owned());
                let has_jwt = jwt.as_deref().is_some_and(is_service_role_jwt);
                if !(line.contains("SERVICE_ROLE") || has_jwt) {
                    continue;
                }
                let snippet = match jwt {
                    Some(t) if has_jwt => short(&line.replace(&t, &mask(&t))),
                    _ => short(line),
                };
                out.push(SEC_002.finding(
                    file,
                    line_no(i),
                    snippet,
                    "This code runs in the browser, and the service-role key skips every Row Level Security rule, so anyone can read and change all of your data with it.".to_owned(),
                    "Use the anon key in the browser and move anything that needs the service-role key into a server route or edge function.".to_owned(),
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------- SEC-003

/// SEC-003: a secret-looking variable with a prefix that sends it to the browser.
pub struct SecretInClientVariable;

const SEC_003_STRONG: Meta = Meta {
    id: "SEC-003",
    title: "Secret exposed through a client variable",
    severity: Severity::High,
    confidence: Confidence::High,
};

const SEC_003_WEAK: Meta = Meta {
    id: "SEC-003",
    title: "Possible secret exposed through a client variable",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
};

/// Names that are public by design even though they say KEY or TOKEN.
const PUBLIC_BY_DESIGN: &[&str] = &[
    "ANON",
    "CLIENT_TOKEN",
    "CLIENT_ID",
    "PUBLISHABLE",
    "PUBLIC_KEY",
    "SITE_KEY",
    "FIREBASE",
    "MAPS",
    "MAPBOX",
    "POSTHOG",
    "SENTRY",
    "ALGOLIA_SEARCH",
    "SEARCH_KEY",
    "RECAPTCHA",
    "TURNSTILE",
    "VAPID_PUBLIC",
    "MEASUREMENT",
    "GA_",
    "GTM",
];

/// Files where a public prefix actually puts a value into the browser bundle: dotenv files and web code.
fn reaches_client_build(file: &SourceFile) -> bool {
    if is_env_file(file) {
        return true;
    }
    !is_noise(file)
        && file.name().rsplit_once('.').is_some_and(|(_, ext)| {
            [
                "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "svelte", "vue", "astro",
                "html",
            ]
            .contains(&ext)
        })
}

fn classify(name: &str) -> Option<&'static Meta> {
    let rest = [
        "NEXT_PUBLIC_",
        "VITE_",
        "EXPO_PUBLIC_",
        "REACT_APP_",
        "PUBLIC_",
    ]
    .iter()
    .find_map(|p| name.strip_prefix(p))
    .unwrap_or(name);
    if ["SECRET", "PRIVATE", "SERVICE_ROLE", "PASSWORD", "PASSWD"]
        .iter()
        .any(|w| rest.contains(w))
    {
        return Some(&SEC_003_STRONG);
    }
    if PUBLIC_BY_DESIGN.iter().any(|w| rest.contains(w)) {
        return None;
    }
    if rest.ends_with("_KEY") || rest == "KEY" || rest.contains("TOKEN") {
        return Some(&SEC_003_WEAK);
    }
    None
}

const SEC_003_INFO: RuleInfo = SEC_003_STRONG.info(
    "Secret-looking variables with a public prefix",
    "Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are copied into the JavaScript every visitor downloads. Names with SECRET, PRIVATE, SERVICE_ROLE or PASSWORD are reported as certain; other _KEY or TOKEN names as worth a look. Keys that are public by design (anon, publishable, Firebase web config, client tokens) are not reported.",
);

impl Rule for SecretInClientVariable {
    fn info(&self) -> &'static RuleInfo {
        &SEC_003_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let Some(re) = CLIENT_VAR.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| reaches_client_build(f)) {
            let Some(text) = file.text() else { continue };
            let mut seen = BTreeSet::new();
            for (i, line) in text.lines().enumerate() {
                for m in re.find_iter(line) {
                    let name = m.as_str();
                    let Some(meta) = classify(name) else { continue };
                    if !seen.insert(name.to_owned()) {
                        continue;
                    }
                    let secrets = secrets_in(line);
                    out.push(meta.finding(
                        file,
                        line_no(i),
                        masked_line(line, &secrets),
                        format!("`{name}` is built into the JavaScript every visitor downloads, so its value is public."),
                        "Rename it without the public prefix and read it only in server code; if it was ever deployed, rotate the value.".to_owned(),
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_role_jwt_is_recognised_and_anon_is_not() {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let service =
            URL_SAFE_NO_PAD.encode(br#"{"iss":"supabase","role":"service_role","iat":1}"#);
        let anon = URL_SAFE_NO_PAD.encode(br#"{"iss":"supabase","role":"anon","iat":1}"#);
        assert!(is_service_role_jwt(&format!(
            "{header}.{service}.c2lnbmF0dXJlLXBhcnQ"
        )));
        assert!(!is_service_role_jwt(&format!(
            "{header}.{anon}.c2lnbmF0dXJlLXBhcnQ"
        )));
    }

    #[test]
    fn client_variable_classification() {
        assert!(
            classify("NEXT_PUBLIC_STRIPE_SECRET_KEY")
                .is_some_and(|m| m.confidence == Confidence::High)
        );
        assert!(
            classify("VITE_SUPABASE_SERVICE_ROLE_KEY")
                .is_some_and(|m| m.confidence == Confidence::High)
        );
        assert!(
            classify("NEXT_PUBLIC_OPENAI_KEY").is_some_and(|m| m.confidence == Confidence::Medium)
        );
        assert!(classify("NEXT_PUBLIC_SUPABASE_ANON_KEY").is_none());
        assert!(classify("NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY").is_none());
        assert!(classify("NEXT_PUBLIC_FIREBASE_API_KEY").is_none());
        assert!(classify("NEXT_PUBLIC_PADDLE_CLIENT_TOKEN").is_none());
        assert!(classify("NEXT_PUBLIC_SITE_URL").is_none());
    }
}
