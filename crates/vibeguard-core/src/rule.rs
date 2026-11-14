//! The rule interface and the list of rules the engine runs.

use std::path::Path;

use crate::Finding;

/// A single check. Rules are stateless: they read the project and return what they found.
pub trait Rule {
    /// Stable id, for example `DB-001`.
    fn id(&self) -> &'static str;
    /// Look at the project under `root` and report findings.
    fn check(&self, root: &Path) -> Vec<Finding>;
}

/// Every rule, in the order they run. Empty until the first rules land.
#[must_use]
pub fn all() -> Vec<Box<dyn Rule>> {
    Vec::new()
}
