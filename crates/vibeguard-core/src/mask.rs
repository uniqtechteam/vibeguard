//! Secret masking. No output format ever shows a full secret.

/// Hide all but a recognisable prefix and the last four characters of a secret.
///
/// `sk_live_51HabcdefWXYZ` becomes `sk_live_****WXYZ`; a short value becomes `****`.
#[must_use]
pub fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 12 {
        return "****".to_owned();
    }
    let prefix_end = chars
        .iter()
        .take(12)
        .rposition(|c| *c == '_' || *c == '-')
        .map_or(0, |i| i + 1);
    let prefix: String = chars[..prefix_end].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}****{tail}")
}

/// Replace every occurrence of `secret` in `text` with its masked form.
#[must_use]
pub fn mask_in(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_owned();
    }
    text.replace(secret, &mask(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_prefix_and_last_four() {
        assert_eq!(mask("sk_live_51HabcdefghijWXYZ"), "sk_live_****WXYZ");
        assert_eq!(mask("ghp_abcdefghijklmnopqrstuvwxyz12"), "ghp_****yz12");
    }

    #[test]
    fn short_values_are_fully_hidden() {
        assert_eq!(mask("abc123"), "****");
    }

    #[test]
    fn no_prefix_keeps_only_the_tail() {
        assert_eq!(mask("AKIAABCDEFGHIJKLMNOP"), "****MNOP");
    }

    #[test]
    fn masks_inside_a_line() {
        let line = "STRIPE_KEY=sk_live_51HabcdefghijWXYZ # prod";
        assert_eq!(
            mask_in(line, "sk_live_51HabcdefghijWXYZ"),
            "STRIPE_KEY=sk_live_****WXYZ # prod"
        );
    }
}
