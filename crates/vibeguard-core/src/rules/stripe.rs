//! PAY-001, PAY-002: Stripe webhooks that trust any caller, and prices chosen by the client.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::{Meta, line_no, short};
use crate::rule::{Rule, RuleInfo};
use crate::{Confidence, Finding, Project, Severity, SourceFile};

fn is_js(file: &SourceFile) -> bool {
    file.name().rsplit_once('.').is_some_and(|(_, ext)| {
        ["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"].contains(&ext)
    })
}

/// A Stripe event name used as a string: `'checkout.session.completed'`, `"invoice.paid"`, ….
static EVENT_NAME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"["'`](?:checkout\.session|invoice|customer\.subscription|payment_intent|charge|customer)\.[a-z_.]+["'`]"#,
    )
    .ok()
});

// ---------------------------------------------------------------- PAY-001

/// PAY-001: a Stripe webhook handler that never verifies the signature.
pub struct UnverifiedWebhook;

const PAY_001: Meta = Meta {
    id: "PAY-001",
    title: "Stripe webhook without signature check",
    severity: Severity::Critical,
    confidence: Confidence::High,
};

const PAY_001_INFO: RuleInfo = PAY_001.info(
    "Stripe webhooks without signature check",
    "A webhook that trusts the posted JSON can be called by anyone with a fake checkout.session.completed and unlock paid features for free. Read the raw body and call stripe.webhooks.constructEvent with the Stripe-Signature header and your webhook secret before acting on the event.",
);

impl Rule for UnverifiedWebhook {
    fn info(&self) -> &'static RuleInfo {
        &PAY_001_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let Some(event) = EVENT_NAME.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| is_js(f)) {
            let Some(text) = file.text() else { continue };
            if !text.to_ascii_lowercase().contains("stripe") || text.contains("constructEvent") {
                continue;
            }
            // a handler reads the event type; a client that only names events is not a webhook
            let handles_events =
                text.contains(".type") && (text.contains("switch") || text.contains("==="));
            if !handles_events {
                continue;
            }
            let Some((i, line)) = text.lines().enumerate().find(|(_, l)| event.is_match(l)) else {
                continue;
            };
            out.push(PAY_001.finding(
                file,
                line_no(i),
                short(line),
                "This webhook acts on Stripe events without checking Stripe's signature, so anyone can send a fake \"payment succeeded\" and get the product for free.".to_owned(),
                "Read the raw body and call `stripe.webhooks.constructEvent(body, signature, webhookSecret)` before trusting the event.".to_owned(),
            ));
        }
        out
    }
}

// ---------------------------------------------------------------- PAY-002

/// PAY-002: the amount charged comes from the request.
pub struct ClientChosenPrice;

const PAY_002: Meta = Meta {
    id: "PAY-002",
    title: "Payment amount taken from the request",
    severity: Severity::High,
    confidence: Confidence::Medium,
};

static CREATE_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"\b(?:checkout\.sessions|paymentIntents|paymentLinks|invoiceItems)\.create\s*\(")
        .ok()
});

/// `const { amount, plan } = await req.json()` / `= req.body` / `= body`.
static DESTRUCTURE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req|request|ctx\.request|event)?\.?(?:body\b|json\(\)|formData\(\))",
    )
    .ok()
});

static AMOUNT_FIELD: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(unit_amount|amount)\b\s*(?::\s*([^,}\n]+))?").ok());

/// Names that came straight out of the request body in this file.
fn body_names(text: &str) -> BTreeSet<String> {
    let Some(re) = DESTRUCTURE.as_ref() else {
        return BTreeSet::new();
    };
    re.captures_iter(text)
        .filter_map(|c| c.get(1))
        .flat_map(|m| {
            m.as_str()
                .split(',')
                .map(|p| {
                    let before_default = p.split('=').next().unwrap_or("");
                    before_default
                        .split(':')
                        .next_back()
                        .unwrap_or("")
                        .trim()
                        .to_owned()
                })
                .filter(|n| !n.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Whether an amount expression is the request value itself (possibly wrapped in `Number(…)` or `* 100`).
fn is_request_value(expr: &str, names: &BTreeSet<String>) -> bool {
    let e = expr.trim().trim_end_matches(',').trim();
    if [
        "req.body",
        "request.body",
        "body.",
        "searchParams",
        "req.query",
        "params.",
    ]
    .iter()
    .any(|p| e.contains(p))
    {
        return true;
    }
    let core = e
        .trim_start_matches("Number(")
        .trim_start_matches("parseInt(")
        .trim_start_matches("parseFloat(")
        .trim_start_matches("Math.round(")
        .split(['*', ')'])
        .next()
        .unwrap_or("")
        .trim();
    names.contains(core)
}

const PAY_002_INFO: RuleInfo = PAY_002.info(
    "Payment amounts taken from the request",
    "When unit_amount or amount comes from the request body, a customer can change it and pay whatever they like. Look the price up on the server from a product id or use a Stripe Price id.",
);

impl Rule for ClientChosenPrice {
    fn info(&self) -> &'static RuleInfo {
        &PAY_002_INFO
    }

    fn check(&self, project: &Project) -> Vec<Finding> {
        let (Some(create), Some(field)) = (CREATE_CALL.as_ref(), AMOUNT_FIELD.as_ref()) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for file in project.files.iter().filter(|f| is_js(f)) {
            let Some(text) = file.text() else { continue };
            if !create.is_match(text) {
                continue;
            }
            let names = body_names(text);
            let lines: Vec<&str> = text.lines().collect();
            let mut reported = BTreeSet::new();
            for (start, _) in lines.iter().enumerate().filter(|(_, l)| create.is_match(l)) {
                for (i, line) in lines.iter().enumerate().skip(start).take(40) {
                    let Some(c) = field.captures(line) else {
                        continue;
                    };
                    let value = c.get(2).map_or_else(
                        // shorthand `{ amount }` uses the variable of the same name
                        || c.get(1).map_or("", |m| m.as_str()),
                        |m| m.as_str(),
                    );
                    if is_request_value(value, &names) && reported.insert(i) {
                        out.push(PAY_002.finding(
                            file,
                            line_no(i),
                            short(line),
                            "The amount charged comes from the request, so a customer can change it and pay whatever they like.".to_owned(),
                            "Look the price up on the server (a Stripe Price id or your own table) from a product id, and never accept an amount from the client.".to_owned(),
                        ));
                    }
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
    fn body_names_reads_destructuring() {
        let n = body_names("const { amount, plan: chosen, qty = 1 } = await req.json()");
        let expected: BTreeSet<String> = ["amount", "chosen", "qty"].map(String::from).into();
        assert_eq!(n, expected);
    }

    #[test]
    fn request_values_and_server_lookups() {
        let names: BTreeSet<String> = ["amount".to_owned(), "plan".to_owned()].into();
        assert!(is_request_value("amount", &names));
        assert!(is_request_value("Number(amount) * 100,", &names));
        assert!(is_request_value("req.body.amount", &names));
        assert!(!is_request_value("PRICES[plan].amount", &names));
        assert!(!is_request_value("2000", &names));
    }
}
