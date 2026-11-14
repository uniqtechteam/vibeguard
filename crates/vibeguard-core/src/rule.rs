//! The rule interface and the list of rules the engine runs.

use crate::{Finding, Project};

/// A single check. Rules are stateless: they read the project and return what they found.
pub trait Rule: Send + Sync {
    /// Stable id, for example `DB-001`.
    fn id(&self) -> &'static str;
    /// Short title, for example `Supabase table without Row Level Security`.
    fn title(&self) -> &'static str;
    /// Look at the project and report findings. Snippets must already be masked.
    fn check(&self, project: &Project) -> Vec<Finding>;
}

/// Every rule, in the order they run.
#[must_use]
pub fn all() -> Vec<Box<dyn Rule>> {
    use crate::rules::secrets::{CommittedSecrets, SecretInClientVariable, ServiceRoleInBrowser};
    vec![
        Box::new(CommittedSecrets),
        Box::new(ServiceRoleInBrowser),
        Box::new(SecretInClientVariable),
    ]
}
