//! The rule interface and the list of rules the engine runs.

use serde::Serialize;

use crate::{Confidence, Finding, Project, Severity};

/// What a rule is, for `vibeguard rules`, `vibeguard explain` and SARIF.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleInfo {
    /// Stable id, for example `DB-001`.
    pub id: &'static str,
    /// Title used on each finding.
    pub title: &'static str,
    /// Highest severity the rule reports.
    pub severity: Severity,
    /// Confidence of its main finding.
    pub confidence: Confidence,
    /// One line for the rule list.
    pub summary: &'static str,
    /// A few sentences: what it finds, why it matters, how to fix it.
    pub explanation: &'static str,
}

/// A single check. Rules are stateless: they read the project and return what they found.
pub trait Rule: Send + Sync {
    /// What this rule is.
    fn info(&self) -> &'static RuleInfo;
    /// Look at the project and report findings. Snippets must already be masked.
    fn check(&self, project: &Project) -> Vec<Finding>;
    /// Stable id, for example `DB-001`.
    fn id(&self) -> &'static str {
        self.info().id
    }
}

/// Every rule, in the order they run.
#[must_use]
pub fn all() -> Vec<Box<dyn Rule>> {
    use crate::rules::secrets::{CommittedSecrets, SecretInClientVariable, ServiceRoleInBrowser};
    use crate::rules::stripe::{ClientChosenPrice, UnverifiedWebhook};
    use crate::rules::supabase::{OpenStorageUpload, OpenWritePolicy, TableWithoutRls};
    vec![
        Box::new(CommittedSecrets),
        Box::new(ServiceRoleInBrowser),
        Box::new(SecretInClientVariable),
        Box::new(TableWithoutRls),
        Box::new(OpenWritePolicy),
        Box::new(OpenStorageUpload),
        Box::new(UnverifiedWebhook),
        Box::new(ClientChosenPrice),
    ]
}

/// Info for every rule, in id order.
#[must_use]
pub fn catalogue() -> Vec<&'static RuleInfo> {
    let mut list: Vec<&'static RuleInfo> = all().iter().map(|r| r.info()).collect();
    list.push(&crate::report::CFG_IGN);
    list.sort_by_key(|i| i.id);
    list
}

/// Info for one rule id (case-insensitive).
#[must_use]
pub fn find(id: &str) -> Option<&'static RuleInfo> {
    catalogue()
        .into_iter()
        .find(|i| i.id.eq_ignore_ascii_case(id))
}
