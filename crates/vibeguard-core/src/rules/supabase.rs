//! DB-001, DB-002, DB-003: Supabase migrations that leave data or storage open.
//!
//! Migrations are read as text: comments are blanked (keeping line numbers), then statements are found
//! with patterns. Supabase migrations are full of PL/pgSQL and policy syntax that general SQL parsers
//! reject, and a parse failure must never hide a real problem.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

use super::{Meta, short};
use crate::rule::Rule;
use crate::{Confidence, Finding, Project, Severity, SourceFile};

/// Supabase migration files, oldest first.
fn migrations(project: &Project) -> Vec<&SourceFile> {
    let mut files: Vec<&SourceFile> = project
        .files
        .iter()
        .filter(|f| {
            std::path::Path::new(&f.path)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("sql"))
                && (f.path.starts_with("supabase/") || f.path.contains("/supabase/"))
                && !f.name().eq_ignore_ascii_case("seed.sql")
        })
        .collect();
    files.sort_by(|a, b| a.name().cmp(b.name()).then_with(|| a.path.cmp(&b.path)));
    files
}

/// Replace `-- …` and `/* … */` comments with spaces, keeping newlines so line numbers stay right.
fn blank_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c as char);
            if c == b'\'' {
                in_string = false;
            }
            i += 1;
        } else if c == b'\'' {
            in_string = true;
            out.push('\'');
            i += 1;
        } else if c == b'-' && bytes.get(i + 1) == Some(&b'-') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
            while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            out.push_str("  ");
            i += 2;
        } else {
            // copy one UTF-8 character
            let ch = sql[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// 1-based line of a byte offset.
fn line_at(text: &str, offset: usize) -> Option<u32> {
    u32::try_from(text[..offset.min(text.len())].matches('\n').count() + 1).ok()
}

/// `public.todos`, `"Public"."Todos"`, `todos` → (schema, table) with unquoted names lowercased.
fn table_key(raw: &str) -> (String, String) {
    let norm = |p: &str| {
        let p = p.trim();
        if let Some(q) = p.strip_prefix('"').and_then(|p| p.strip_suffix('"')) {
            q.to_owned()
        } else {
            p.to_ascii_lowercase()
        }
    };
    match raw.split_once('.') {
        Some((schema, table)) => (norm(schema), norm(table)),
        None => ("public".to_owned(), norm(raw)),
    }
}

const NAME: &str =
    r#"((?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_$]*))?)"#;

static CREATE_TABLE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)\bcreate\s+(?:(?:global|local)\s+)?(?:temp(?:orary)?\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?{NAME}"
    ))
    .ok()
});

static ENABLE_RLS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?{NAME}\s+enable\s+row\s+level\s+security"
    ))
    .ok()
});

static DROP_TABLE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(&format!(r"(?i)\bdrop\s+table\s+(?:if\s+exists\s+)?{NAME}")).ok());

/// Schemas Supabase exposes through its API; tables elsewhere are not reachable with the anon key.
const EXPOSED_SCHEMAS: &[&str] = &["public"];

// ---------------------------------------------------------------- DB-001

/// DB-001: a table in an exposed schema that never gets Row Level Security.
pub struct TableWithoutRls;

const DB_001: Meta = Meta {
    id: "DB-001",
    title: "Supabase table without Row Level Security",
    severity: Severity::Critical,
    confidence: Confidence::High,
};

impl Rule for TableWithoutRls {
    fn id(&self) -> &'static str {
        DB_001.id
    }

    fn title(&self) -> &'static str {
        DB_001.title
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let (Some(create), Some(enable), Some(drop)) = (
            CREATE_TABLE.as_ref(),
            ENABLE_RLS.as_ref(),
            DROP_TABLE.as_ref(),
        ) else {
            return Vec::new();
        };
        // (schema, table) → (file, line, snippet) of the CREATE TABLE still standing
        let mut created: BTreeMap<(String, String), (&SourceFile, Option<u32>, String)> =
            BTreeMap::new();
        let mut protected: BTreeSet<(String, String)> = BTreeSet::new();
        for file in migrations(project) {
            let Some(text) = file.text() else { continue };
            let sql = blank_comments(text);
            let mut events: Vec<(usize, u8, (String, String))> = Vec::new();
            for c in create.captures_iter(&sql) {
                if let (Some(all), Some(n)) = (c.get(0), c.get(1)) {
                    events.push((all.start(), 0, table_key(n.as_str())));
                }
            }
            for c in enable.captures_iter(&sql) {
                if let (Some(all), Some(n)) = (c.get(0), c.get(1)) {
                    events.push((all.start(), 1, table_key(n.as_str())));
                }
            }
            for c in drop.captures_iter(&sql) {
                if let (Some(all), Some(n)) = (c.get(0), c.get(1)) {
                    events.push((all.start(), 2, table_key(n.as_str())));
                }
            }
            events.sort();
            for (offset, kind, key) in events {
                match kind {
                    0 => {
                        let line = line_at(&sql, offset);
                        let snippet = text
                            .lines()
                            .nth(line.map_or(0, |l| l as usize - 1))
                            .map(short)
                            .unwrap_or_default();
                        protected.remove(&key);
                        created.insert(key, (file, line, snippet));
                    }
                    1 => {
                        protected.insert(key);
                    }
                    _ => {
                        created.remove(&key);
                        protected.remove(&key);
                    }
                }
            }
        }
        created
            .into_iter()
            .filter(|(key, _)| EXPOSED_SCHEMAS.contains(&key.0.as_str()) && !protected.contains(key))
            .map(|((_, table), (file, line, snippet))| {
                DB_001.finding(
                    file,
                    line,
                    snippet,
                    format!("Table `{table}` has no Row Level Security, so anyone with your public anon key can read and change every row."),
                    format!("Add `alter table {table} enable row level security;` in a migration, then add policies that limit rows to their owner."),
                )
            })
            .collect()
    }
}

// ---------------------------------------------------------------- DB-002 and DB-003

/// One `create policy` statement.
struct Policy<'a> {
    file: &'a SourceFile,
    line: Option<u32>,
    table: (String, String),
    command: String,
    roles: Vec<String>,
    using: Option<String>,
    check: Option<String>,
    snippet: String,
}

static POLICY: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?is)\bcreate\s+policy\s+(?:"[^"]*"|\S+)\s+on\s+{NAME}([^;]*)"#
    ))
    .ok()
});

static FOR_CMD: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)\bfor\s+(all|select|insert|update|delete)\b").ok());

static TO_ROLES: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)\bto\s+(.+?)(?:\busing\b|\bwith\s+check\b|$)").ok());

/// The text inside the parentheses after `keyword (`, balancing nested parentheses.
fn clause(body: &str, keyword: &Regex) -> Option<String> {
    let m = keyword.find(body)?;
    let rest = &body[m.end()..];
    let open = rest.find('(')?;
    let mut depth = 0usize;
    for (i, ch) in rest[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[open + 1..open + i].trim().to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

static USING_KW: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"(?i)\busing\b").ok());
static CHECK_KW: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)\bwith\s+check\b").ok());

fn policies(project: &Project) -> Vec<Policy<'_>> {
    let (Some(policy), Some(for_cmd), Some(to_roles), Some(using_kw), Some(check_kw)) = (
        POLICY.as_ref(),
        FOR_CMD.as_ref(),
        TO_ROLES.as_ref(),
        USING_KW.as_ref(),
        CHECK_KW.as_ref(),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for file in migrations(project) {
        let Some(text) = file.text() else { continue };
        let sql = blank_comments(text);
        for c in policy.captures_iter(&sql) {
            let (Some(all), Some(name), Some(body)) = (c.get(0), c.get(1), c.get(2)) else {
                continue;
            };
            let body = body.as_str();
            let command = for_cmd
                .captures(body)
                .and_then(|m| m.get(1))
                .map_or_else(|| "all".to_owned(), |m| m.as_str().to_ascii_lowercase());
            let roles = to_roles.captures(body).and_then(|m| m.get(1)).map_or_else(
                || vec!["public".to_owned()],
                |m| {
                    m.as_str()
                        .split(',')
                        .map(|r| r.trim().trim_matches('"').to_ascii_lowercase())
                        .filter(|r| !r.is_empty())
                        .collect()
                },
            );
            let line = line_at(&sql, all.start());
            out.push(Policy {
                file,
                line,
                table: table_key(name.as_str()),
                command,
                roles,
                using: clause(body, using_kw),
                check: clause(body, check_kw),
                snippet: text
                    .lines()
                    .nth(line.map_or(0, |l| l as usize - 1))
                    .map(short)
                    .unwrap_or_default(),
            });
        }
    }
    out
}

fn is_true(expr: Option<&str>) -> bool {
    expr.is_some_and(|e| {
        e.trim()
            .trim_matches(|c| c == '(' || c == ')')
            .trim()
            .eq_ignore_ascii_case("true")
    })
}

const OPEN_ROLES: &[&str] = &["anon", "public", "authenticated"];

/// DB-002: a policy that lets anyone (or any signed-in user) write every row.
pub struct OpenWritePolicy;

const DB_002: Meta = Meta {
    id: "DB-002",
    title: "Row Level Security policy that lets anyone write",
    severity: Severity::High,
    confidence: Confidence::High,
};

impl Rule for OpenWritePolicy {
    fn id(&self) -> &'static str {
        DB_002.id
    }

    fn title(&self) -> &'static str {
        DB_002.title
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        policies(project)
            .into_iter()
            .filter(|p| p.table.0 != "storage")
            .filter(|p| matches!(p.command.as_str(), "insert" | "update" | "delete" | "all"))
            .filter(|p| p.roles.iter().any(|r| OPEN_ROLES.contains(&r.as_str())))
            .filter(|p| is_true(p.using.as_deref()) || is_true(p.check.as_deref()))
            .map(|p| {
                let who = if p.roles.iter().all(|r| r == "authenticated") {
                    "any signed-in user"
                } else {
                    "anyone"
                };
                DB_002.finding(
                    p.file,
                    p.line,
                    p.snippet,
                    format!("This policy on `{}` lets {who} {} any row, because its condition is just `true`.", p.table.1, if p.command == "all" { "change" } else { p.command.as_str() }),
                    "Replace `true` with a real check, for example `auth.uid() = user_id`.".to_owned(),
                )
            })
            .collect()
    }
}

static PUBLIC_BUCKET: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?is)\binsert\s+into\s+storage\.buckets\b[^;]*?\btrue\b").ok());

/// DB-003: a public storage bucket with an upload policy that does not check who uploads.
pub struct OpenStorageUpload;

const DB_003: Meta = Meta {
    id: "DB-003",
    title: "Public storage bucket that anyone can upload to",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
};

impl Rule for OpenStorageUpload {
    fn id(&self) -> &'static str {
        DB_003.id
    }

    fn title(&self) -> &'static str {
        DB_003.title
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let Some(bucket) = PUBLIC_BUCKET.as_ref() else {
            return Vec::new();
        };
        let has_public_bucket = migrations(project)
            .iter()
            .filter_map(|f| f.text())
            .any(|t| bucket.is_match(&blank_comments(t)));
        if !has_public_bucket {
            return Vec::new();
        }
        policies(project)
            .into_iter()
            .filter(|p| p.table == ("storage".to_owned(), "objects".to_owned()))
            .filter(|p| matches!(p.command.as_str(), "insert" | "all"))
            .filter(|p| p.roles.iter().any(|r| r == "anon" || r == "public"))
            .filter(|p| {
                let cond = p.check.as_deref().or(p.using.as_deref()).unwrap_or("true");
                !cond.to_ascii_lowercase().contains("auth.")
            })
            .map(|p| {
                DB_003.finding(
                    p.file,
                    p.line,
                    p.snippet,
                    "A public bucket accepts uploads without checking who is uploading, so anyone can host files on your storage and your bill.".to_owned(),
                    "Limit uploads to signed-in users, for example `with check (bucket_id = 'avatars' and auth.uid() is not null)`, and scope paths to the user's id.".to_owned(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_blanked_but_lines_kept() {
        let sql = "create table a (); -- enable row level security\n/* x\ny */ select 1;";
        let b = blank_comments(sql);
        assert_eq!(b.matches('\n').count(), sql.matches('\n').count());
        assert!(!b.contains("enable"));
    }

    #[test]
    fn table_keys_normalise_case_and_quotes() {
        assert_eq!(table_key("Todos"), ("public".into(), "todos".into()));
        assert_eq!(
            table_key("\"public\".\"Todos\""),
            ("public".into(), "Todos".into())
        );
        assert_eq!(
            table_key("private . audit"),
            ("private".into(), "audit".into())
        );
    }
}
