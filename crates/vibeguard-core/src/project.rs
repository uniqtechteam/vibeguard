//! The project being scanned: which files exist, their contents (read once, on demand) and which stack
//! the app uses.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ignore::WalkBuilder;
use serde::Serialize;

/// Files larger than this are skipped: generated bundles and data dumps, not source.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Folders never worth reading, even when a project forgot to ignore them.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    ".turbo",
    "dist",
    "build",
    "out",
    "coverage",
    ".git",
    "target",
    "vendor",
];

/// A framework or service the project uses. Rules check this to skip work that cannot apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stack {
    /// Next.js (`next` dependency or a `next.config.*`).
    NextJs,
    /// Vite (`vite` dependency or a `vite.config.*`).
    Vite,
    /// Supabase (`@supabase/*` dependency or a `supabase/` folder).
    Supabase,
    /// Firebase (`firebase` / `firebase-admin` dependency, `firebase.json` or `*.rules`).
    Firebase,
    /// Stripe (`stripe` / `@stripe/*` dependency).
    Stripe,
}

/// One file in the project.
#[derive(Debug)]
pub struct SourceFile {
    /// Path relative to the project root, with forward slashes.
    pub path: String,
    abs: PathBuf,
    text: OnceLock<Option<String>>,
}

impl SourceFile {
    /// The file as UTF-8 text, read the first time it is asked for. `None` for binary or unreadable files.
    pub fn text(&self) -> Option<&str> {
        self.text
            .get_or_init(|| {
                let bytes = fs::read(&self.abs).ok()?;
                if bytes.iter().take(8000).any(|b| *b == 0) {
                    return None;
                }
                String::from_utf8(bytes).ok()
            })
            .as_deref()
    }

    /// The file name, for example `route.ts`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// The project on disk.
#[derive(Debug)]
pub struct Project {
    /// Absolute root that was scanned.
    pub root: PathBuf,
    /// Every file worth reading, sorted by path.
    pub files: Vec<SourceFile>,
    /// What the app is built with.
    pub stack: BTreeSet<Stack>,
}

impl Project {
    /// Walk `root`, honouring `.gitignore` and the default skips, and detect the stack.
    ///
    /// # Errors
    /// When `root` does not exist or is not a directory.
    pub fn load(root: &Path) -> std::io::Result<Self> {
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                format!("{} is not a folder", root.display()),
            ));
        }
        let mut files = Vec::new();
        let walker = WalkBuilder::new(&root)
            .hidden(false)
            .git_ignore(true)
            .git_global(false)
            .git_exclude(true)
            .require_git(false)
            .filter_entry(|e| {
                !(e.file_type().is_some_and(|t| t.is_dir())
                    && SKIP_DIRS.contains(&e.file_name().to_string_lossy().as_ref()))
            })
            .build();
        for entry in walker.flatten() {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            if entry.metadata().is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
                continue;
            }
            let Ok(rel) = entry.path().strip_prefix(&root) else {
                continue;
            };
            let path = rel.to_string_lossy().replace('\\', "/");
            files.push(SourceFile {
                path,
                abs: entry.path().to_path_buf(),
                text: OnceLock::new(),
            });
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut project = Self {
            root,
            files,
            stack: BTreeSet::new(),
        };
        project.stack = detect_stack(&project);
        Ok(project)
    }

    /// A file by its relative path.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&SourceFile> {
        self.files.iter().find(|f| f.path == path)
    }

    /// Whether the project uses `stack`.
    #[must_use]
    pub fn uses(&self, stack: Stack) -> bool {
        self.stack.contains(&stack)
    }
}

fn detect_stack(project: &Project) -> BTreeSet<Stack> {
    let mut stack = BTreeSet::new();
    for file in project.files.iter().filter(|f| f.name() == "package.json") {
        let Some(json) = file
            .text()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
        else {
            continue;
        };
        for section in ["dependencies", "devDependencies"] {
            let Some(deps) = json.get(section).and_then(serde_json::Value::as_object) else {
                continue;
            };
            for name in deps.keys() {
                match name.as_str() {
                    "next" => stack.insert(Stack::NextJs),
                    "vite" => stack.insert(Stack::Vite),
                    "firebase" | "firebase-admin" => stack.insert(Stack::Firebase),
                    "stripe" => stack.insert(Stack::Stripe),
                    n if n.starts_with("@supabase/") => stack.insert(Stack::Supabase),
                    n if n.starts_with("@stripe/") => stack.insert(Stack::Stripe),
                    _ => false,
                };
            }
        }
    }
    for file in &project.files {
        let p = file.path.as_str();
        let name = file.name();
        if name.starts_with("next.config.") {
            stack.insert(Stack::NextJs);
        } else if name.starts_with("vite.config.") {
            stack.insert(Stack::Vite);
        } else if name == "firebase.json" || name == "firestore.rules" || name == "storage.rules" {
            stack.insert(Stack::Firebase);
        } else if p.starts_with("supabase/") || p.contains("/supabase/") {
            stack.insert(Stack::Supabase);
        }
    }
    stack
}
