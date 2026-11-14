//! API-001: Next.js routes that change data without checking who is asking.

use std::sync::LazyLock;

use regex::Regex;

use super::{Meta, line_no, short};
use crate::rule::{Rule, RuleInfo};
use crate::{Confidence, Finding, Project, Severity, SourceFile};

/// `export async function POST(` / `export const DELETE =`.
static APP_HANDLER: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"export\s+(?:async\s+)?(?:function\s+|const\s+)(POST|PUT|PATCH|DELETE)\b").ok()
});

/// A database write in a `pages/api` handler.
static DB_WRITE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\.(?:insert|update|upsert|delete|create|createMany|updateMany|deleteMany|destroy|remove|set|add)\s*\(").ok()
});

/// Calls that check who is asking: sessions, tokens, signatures, shared secrets.
const AUTH_MARKERS: &[&str] = &[
    "auth(",
    "getServerSession",
    "getSession",
    "getUser",
    "currentUser",
    "getToken",
    "verifyIdToken",
    "verifyToken",
    "jwt.verify",
    "jwtVerify",
    "requireAuth",
    "requireUser",
    "withAuth",
    "withApiAuth",
    "getAuth(",
    "supabase.auth",
    "validateRequest",
    "clerkClient",
    "constructEvent",
    "verifySignature",
    "authorization",
    "Authorization",
    "x-api-key",
    "CRON_SECRET",
    "API_SECRET",
    "isAdmin",
];

fn has_auth(text: &str) -> bool {
    AUTH_MARKERS.iter().any(|m| text.contains(m))
}

/// `app/(shop)/api/orders/[id]/route.ts` → `/api/orders/[id]`.
fn route_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("src/").unwrap_or(path);
    let rest = rest
        .strip_prefix("app/")
        .or_else(|| rest.strip_prefix("pages/"))?;
    let dir = rest.rsplit_once('/').map_or("", |(d, _)| d);
    let file_stem = rest
        .rsplit('/')
        .next()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    let mut parts: Vec<&str> = dir
        .split('/')
        .filter(|p| !p.is_empty() && !p.starts_with('('))
        .collect();
    if path.contains("pages/") && file_stem != "index" {
        parts.push(file_stem);
    }
    Some(format!("/{}", parts.join("/")))
}

/// Paths covered by an authenticating `middleware.ts`. `None` = no such middleware; an empty list =
/// it runs on every path.
fn middleware_cover(project: &Project) -> Option<Vec<String>> {
    let mw = project.files.iter().find(|f| {
        matches!(
            f.path.as_str(),
            "middleware.ts" | "middleware.js" | "src/middleware.ts" | "src/middleware.js"
        )
    })?;
    let text = mw.text()?;
    if !has_auth(text) && !text.contains("updateSession") {
        return None;
    }
    let Some(start) = text.find("matcher") else {
        return Some(Vec::new());
    };
    let section = &text[start..];
    let end = section.find(['}', ']']).map_or(section.len(), |i| i + 1);
    let quoted = Regex::new(r#"["'`]([^"'`]+)["'`]"#).ok()?;
    Some(
        quoted
            .captures_iter(&section[..end])
            .filter_map(|c| c.get(1))
            .map(|m| {
                m.as_str()
                    .split([':', '(', '*'])
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .to_owned()
            })
            .collect(),
    )
}

fn covered(route: &str, cover: Option<&Vec<String>>) -> bool {
    match cover {
        None => false,
        Some(prefixes) if prefixes.is_empty() => true,
        Some(prefixes) => prefixes
            .iter()
            .any(|p| p.is_empty() || route.starts_with(p.as_str())),
    }
}

/// API-001: a route that changes data without checking who is asking.
pub struct UnprotectedRoute;

const API_001: Meta = Meta {
    id: "API-001",
    title: "Route that changes data without an auth check",
    severity: Severity::High,
    confidence: Confidence::Medium,
};

const API_001_INFO: RuleInfo = API_001.info(
    "Routes that change data without checking who is asking",
    "A Next.js route handler that exports POST, PUT, PATCH or DELETE (or a pages/api handler that writes to the database) with no session, token or signature check can be called by anyone with curl. vibeguard looks for common auth calls in the file and for an authenticating middleware.ts whose matcher covers the route. It is a heuristic, so read the code before acting.",
);

fn is_route_file(file: &SourceFile) -> bool {
    let p = file.path.as_str();
    let js = std::path::Path::new(file.name())
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| ["ts", "js", "mjs", "tsx", "jsx"].contains(&e));
    js && ((p.starts_with("app/") || p.starts_with("src/app/"))
        && file.name().starts_with("route.")
        || (p.starts_with("pages/api/") || p.starts_with("src/pages/api/")))
}

impl Rule for UnprotectedRoute {
    fn info(&self) -> &'static RuleInfo {
        &API_001_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let (Some(handler), Some(db_write)) = (APP_HANDLER.as_ref(), DB_WRITE.as_ref()) else {
            return Vec::new();
        };
        let cover = middleware_cover(project);
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| is_route_file(f)) {
            let Some(text) = file.text() else { continue };
            // an unverified Stripe webhook is PAY-001's job; do not report the same route twice
            if has_auth(text) || (text.contains("stripe") && text.contains("event.type")) {
                continue;
            }
            let route = route_path(&file.path).unwrap_or_default();
            if covered(&route, cover.as_ref()) {
                continue;
            }
            let app_router = file.name().starts_with("route.");
            let hit = text.lines().enumerate().find(|(_, l)| {
                if app_router {
                    handler.is_match(l)
                } else {
                    db_write.is_match(l)
                }
            });
            let Some((i, line)) = hit else { continue };
            out.push(API_001.finding(
                file,
                line_no(i),
                short(line),
                format!("`{route}` changes data but nothing in this file checks who is calling, so anyone can call it directly."),
                "Check the session or token at the top of the handler (for example `const { data: { user } } = await supabase.auth.getUser()` and return 401 when there is none), or protect the path in middleware.ts.".to_owned(),
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::route_path;

    #[test]
    fn route_paths_drop_groups_and_route_files() {
        assert_eq!(
            route_path("app/(shop)/api/orders/[id]/route.ts").as_deref(),
            Some("/api/orders/[id]")
        );
        assert_eq!(
            route_path("src/app/api/todos/route.ts").as_deref(),
            Some("/api/todos")
        );
        assert_eq!(
            route_path("pages/api/users/create.ts").as_deref(),
            Some("/api/users/create")
        );
        assert_eq!(route_path("pages/api/index.ts").as_deref(), Some("/api"));
    }
}
