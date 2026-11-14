//! FB-001: Firestore, Storage or Realtime Database rules that let anyone write.

use std::sync::LazyLock;

use regex::Regex;

use super::{Meta, line_no, short};
use crate::rule::{Rule, RuleInfo};
use crate::{Confidence, Finding, Project, Severity, SourceFile};

/// `allow <ops>;` or `allow <ops>: if true;`
static OPEN_ALLOW: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\ballow\s+([a-z ,]+?)\s*(?::\s*if\s+true\s*)?;").ok());

/// The "test mode" rule Firebase generates: open to everyone until a date.
static TEST_MODE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\ballow\s+[a-z ,]+:\s*if\s+request\.time\s*<\s*timestamp\.date\(").ok()
});

/// Realtime Database JSON: `".write": true` or `".write": "true"`.
static RTDB_WRITE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#""\.write"\s*:\s*"?true"?"#).ok());

const WRITE_OPS: &[&str] = &["write", "create", "update", "delete"];

fn is_rules_file(file: &SourceFile) -> bool {
    let name = file.name();
    std::path::Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("rules"))
        || name == "database.rules.json"
}

/// FB-001: Firebase security rules that let anyone write.
pub struct OpenFirebaseRules;

const FB_001: Meta = Meta {
    id: "FB-001",
    title: "Firebase rules open to everyone",
    severity: Severity::Critical,
    confidence: Confidence::High,
};

const FB_001_INFO: RuleInfo = FB_001.info(
    "Firestore, Storage or Realtime Database rules that let anyone write",
    "Rules like `allow read, write: if true;`, an `allow write;` with no condition, the generated \"test mode\" rule that stays open until a date, or `\".write\": true` in database.rules.json let anyone on the internet change or delete your data. Write rules that check `request.auth` and the document owner, and only allow public reads where the data really is public.",
);

impl Rule for OpenFirebaseRules {
    fn info(&self) -> &'static RuleInfo {
        &FB_001_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let (Some(open), Some(test_mode), Some(rtdb)) =
            (OPEN_ALLOW.as_ref(), TEST_MODE.as_ref(), RTDB_WRITE.as_ref())
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| is_rules_file(f)) {
            let Some(text) = file.text() else { continue };
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                let why = if test_mode.is_match(code) {
                    Some("This is Firebase's \"test mode\" rule: anyone can read and write your data until the date passes, and many apps go live with it.".to_owned())
                } else if let Some(c) = open.captures(code) {
                    let ops = c.get(1).map_or("", |m| m.as_str());
                    let writes = ops
                        .split(',')
                        .map(str::trim)
                        .any(|op| WRITE_OPS.contains(&op));
                    writes.then(|| format!("`allow {}` with no real condition lets anyone on the internet change your data.", ops.trim()))
                } else if rtdb.is_match(code) {
                    Some("`.write` is `true`, so anyone can overwrite or delete this part of your Realtime Database.".to_owned())
                } else {
                    None
                };
                if let Some(why) = why {
                    out.push(FB_001.finding(
                        file,
                        line_no(i),
                        short(line),
                        why,
                        "Require a signed-in owner, for example `allow write: if request.auth != null && request.auth.uid == resource.data.ownerId;`.".to_owned(),
                    ));
                }
            }
        }
        out
    }
}
