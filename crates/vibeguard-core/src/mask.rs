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

    // Test secrets are assembled from pieces so no key-shaped string sits in the repository.
    fn fake(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn keeps_prefix_and_last_four() {
        assert_eq!(
            mask(&fake(&["sk", "_live_", "51Habcdefghij", "WXYZ"])),
            "sk_live_****WXYZ"
        );
        assert_eq!(
            mask(&fake(&["ghp", "_abcdefghijklmnopqrstuvwxyz", "12"])),
            "ghp_****yz12"
        );
    }

    #[test]
    fn short_values_are_fully_hidden() {
        assert_eq!(mask("abc123"), "****");
    }

    #[test]
    fn no_prefix_keeps_only_the_tail() {
        assert_eq!(mask(&fake(&["AKIA", "ABCDEFGHIJKL", "MNOP"])), "****MNOP");
    }

    #[test]
    fn masks_inside_a_line() {
        let key = fake(&["sk", "_live_", "51Habcdefghij", "WXYZ"]);
        let line = format!("STRIPE_KEY={key} # prod");
        assert_eq!(mask_in(&line, &key), "STRIPE_KEY=sk_live_****WXYZ # prod");
    }
}
