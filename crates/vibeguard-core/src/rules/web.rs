//! WEB-001 (CORS that trusts every site with credentials) and CFG-001 (launch-unsafe build settings).

use std::sync::LazyLock;

use regex::Regex;

use super::{Meta, line_no, short};
use crate::rule::{Rule, RuleInfo};
use crate::{Confidence, Finding, Project, Severity, SourceFile};

fn is_js(file: &SourceFile) -> bool {
    std::path::Path::new(file.name())
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"].contains(&e))
}

// ---------------------------------------------------------------- WEB-001

/// `origin: true` / `origin: '*'` / `origin: (o, cb) => cb(null, true)` / a header copied from the request.
static ANY_ORIGIN: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\borigin\s*:\s*(?:true|["'`]\*["'`]|\(\s*\w+\s*,\s*\w+\s*\)\s*=>\s*\w+\(\s*null\s*,\s*true\s*\))|access-control-allow-origin["'`]?\s*[,:]\s*(?:["'`]\*["'`]|\w+\.headers(?:\.get\(\s*["'`]origin["'`]\s*\)|\.origin|\[["'`]origin["'`]\])))"#,
    )
    .ok()
});

static CREDENTIALS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bcredentials\s*:\s*true|access-control-allow-credentials["'`]?\s*[,:]\s*["'`]?true)"#).ok()
});

/// The code that must also allow credentials for a match at `offset` to matter: the enclosing
/// `{ … }` options object for `origin:` forms, or a few lines around a header being set.
fn scope_around<'a>(text: &'a str, lines: &[&str], offset: usize) -> &'a str {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for i in (0..offset).rev() {
        match bytes[i] {
            b'}' => depth += 1,
            b'{' if depth == 0 => {
                open = Some(i);
                break;
            }
            b'{' => depth -= 1,
            b'\n' if offset - i > 2000 => break,
            _ => {}
        }
    }
    let line = text[..offset].matches('\n').count();
    let is_header = text[offset..]
        .to_ascii_lowercase()
        .starts_with("access-control");
    if let (Some(start), false) = (open, is_header) {
        let mut depth = 0i32;
        for (j, b) in bytes.iter().enumerate().skip(start) {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[start..=j];
                    }
                }
                _ => {}
            }
        }
    }
    let from = line.saturating_sub(6);
    let to = (line + 6).min(lines.len().saturating_sub(1));
    let start = lines[..from]
        .iter()
        .map(|l| l.len() + 1)
        .sum::<usize>()
        .min(text.len());
    let end = lines[..=to]
        .iter()
        .map(|l| l.len() + 1)
        .sum::<usize>()
        .min(text.len());
    &text[start..end]
}

/// WEB-001: CORS that lets every site make logged-in requests.
pub struct OpenCors;

const WEB_001: Meta = Meta {
    id: "WEB-001",
    title: "CORS open to every site with credentials",
    severity: Severity::Medium,
    confidence: Confidence::High,
};

const WEB_001_INFO: RuleInfo = WEB_001.info(
    "CORS that lets every site make requests with the user's cookies",
    "Allowing every origin (`origin: true`, `*`, or copying the request's Origin header) while also allowing credentials means any website a user visits can call your API as that user and read the answer. List the origins you trust instead, or drop credentials for public endpoints.",
);

impl Rule for OpenCors {
    fn info(&self) -> &'static RuleInfo {
        &WEB_001_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let (Some(any), Some(creds)) = (ANY_ORIGIN.as_ref(), CREDENTIALS.as_ref()) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| is_js(f)) {
            let Some(text) = file.text() else { continue };
            if !creds.is_match(text) {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            let mut reported = std::collections::BTreeSet::new();
            for m in any.find_iter(text) {
                if !creds.is_match(scope_around(text, &lines, m.start())) {
                    continue;
                }
                let i = text[..m.start()].matches('\n').count();
                if !reported.insert(i) {
                    continue;
                }
                out.push(WEB_001.finding(
                    file,
                    line_no(i),
                    short(lines.get(i).copied().unwrap_or("")),
                    "This allows every website to send requests with your users' cookies and read the replies.".to_owned(),
                    "Replace it with an allow-list such as `origin: ['https://your-app.com']`, or turn credentials off.".to_owned(),
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------- CFG-001

/// (pattern, what it does)
static UNSAFE_SETTINGS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (
            r"\bignoreBuildErrors\s*:\s*true",
            "Type errors no longer stop the build, so broken code can ship.",
        ),
        (
            r"\bignoreDuringBuilds\s*:\s*true",
            "Lint errors no longer stop the build.",
        ),
        (
            r"\bproductionBrowserSourceMaps\s*:\s*true",
            "Your original source code is published next to the site.",
        ),
        (
            r"\bsourcemap\s*:\s*true",
            "Source maps ship with the build, so your original source code is public.",
        ),
    ]
    .into_iter()
    .filter_map(|(re, why)| Regex::new(re).ok().map(|r| (r, why)))
    .collect()
});

/// CFG-001: build settings that are fine while hacking and wrong at launch.
pub struct UnsafeBuildSettings;

const CFG_001: Meta = Meta {
    id: "CFG-001",
    title: "Launch-unsafe build setting",
    severity: Severity::Low,
    confidence: Confidence::High,
};

const CFG_001_INFO: RuleInfo = CFG_001.info(
    "Build settings that hide errors or publish source maps",
    "AI tools often turn off type and lint errors to get a build through (`ignoreBuildErrors`, `ignoreDuringBuilds`) and leave production source maps on. The first lets broken code ship; the second publishes your original source. Fix the errors and turn the settings back off before launch.",
);

impl Rule for UnsafeBuildSettings {
    fn info(&self) -> &'static RuleInfo {
        &CFG_001_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let mut out = Vec::new();
        let configs = project.files.iter().filter(|f| {
            f.name().starts_with("next.config.") || f.name().starts_with("vite.config.")
        });
        for file in configs {
            let Some(text) = file.text() else { continue };
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if let Some((_, why)) = UNSAFE_SETTINGS.iter().find(|(re, _)| re.is_match(code)) {
                    out.push(CFG_001.finding(
                        file,
                        line_no(i),
                        short(line),
                        (*why).to_owned(),
                        "Fix what the setting was hiding, then remove it (or set it to false) before launch.".to_owned(),
                    ));
                }
            }
        }
        out
    }
}
