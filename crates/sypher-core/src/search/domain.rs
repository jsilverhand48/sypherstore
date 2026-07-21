//! Hostname normalization and domain matching.
//!
//! The problem this solves: the user is on `https://mail.google.com/u/0/#inbox`
//! and their secret is filed under `google.com`. A naive string comparison
//! misses it, and a naive suffix comparison wrongly matches `notgoogle.com`
//! and, worse, matches everything under `co.uk` against everything else under
//! `co.uk`.
//!
//! The fix is the Public Suffix List, via the `psl` crate. It knows that the
//! registrable domain of `mail.google.com` is `google.com` but that of
//! `bbc.co.uk` is `bbc.co.uk`, because `co.uk` is itself a public suffix. That
//! distinction is not derivable from the string alone, which is why a
//! hand-rolled "last two labels" rule is wrong.

/// How well a stored secret's domain matches the browser's current hostname.
///
/// Ordered worst to best so that `derive(Ord)` sorts correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DomainMatch {
    /// Unrelated hosts.
    None,
    /// Same registrable domain, different subdomains, e.g. `mail.google.com`
    /// against a secret filed under `calendar.google.com`.
    RegistrableDomain,
    /// The secret's domain is a parent of the current host, e.g. a
    /// `github.com` secret on `api.github.com`.
    ParentDomain,
    /// Identical hostnames.
    Exact,
}

impl DomainMatch {
    /// Whether this match should make the secret appear in a filtered list.
    pub fn is_match(&self) -> bool {
        !matches!(self, DomainMatch::None)
    }
}

/// Reduces a URL or bare hostname to a comparable lowercase hostname.
///
/// Strips scheme, credentials, port, path, query and fragment, plus a leading
/// `www.` and a trailing dot. Returns `None` when nothing hostname-shaped is
/// left, which is the correct outcome for `about:blank` or a `file://` URL and
/// makes the caller fall back to showing everything.
pub fn normalize_host(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }

    // Reject schemes that never name a remote host, before any parsing. These
    // are the internal pages a browser is often sitting on, and filtering the
    // popup by "settings" or "newtab" would be nonsense.
    //
    // Note `file:` and `chrome:` must be caught here rather than after
    // splitting on `://`, since `chrome://settings` is authority-shaped and
    // would otherwise normalize to the host `settings`.
    const HOSTLESS_SCHEMES: [&str; 8] = [
        "about", "data", "javascript", "chrome", "file", "blob", "view-source",
        "moz-extension",
    ];
    if let Some(i) = s.find(':') {
        let scheme = &s[..i];
        if HOSTLESS_SCHEMES
            .iter()
            .any(|h| scheme.eq_ignore_ascii_case(h))
        {
            return None;
        }
    }

    // Strip the scheme if there is one. A bare `host:port` has no `://` and
    // keeps its authority intact for the port-stripping step below.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s,
    };

    // Cut off everything after the authority.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);

    // Drop `user:pass@`.
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };

    // Drop the port, taking care not to mangle a bracketed IPv6 literal.
    let host = if host_port.starts_with('[') {
        match host_port.find(']') {
            Some(i) => &host_port[..=i],
            None => host_port,
        }
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };

    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();

    if host.is_empty() || !host.contains(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(host)
}

/// Returns the registrable domain ("eTLD+1") of a hostname.
///
/// `mail.google.com` yields `google.com`; `bbc.co.uk` yields `bbc.co.uk`.
/// Returns `None` for IP literals and hosts with no recognized public suffix,
/// where the concept does not apply.
pub fn registrable_domain(host: &str) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return None;
    }
    let domain = psl::domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(|s| s.to_ascii_lowercase())
}

/// Classifies how a stored `secret_domain` relates to the browser's `host`.
///
/// Both sides are normalized first, so a secret filed as
/// `https://www.GitHub.com/login` still matches `github.com`.
pub fn match_domain(secret_domain: &str, host: &str) -> DomainMatch {
    let (Some(secret), Some(current)) = (normalize_host(secret_domain), normalize_host(host))
    else {
        return DomainMatch::None;
    };

    if secret == current {
        return DomainMatch::Exact;
    }

    // A parent-domain match means the secret is filed at `github.com` and we
    // are on `api.github.com`. The label boundary check is what stops
    // `notgithub.com` from matching a `github.com` secret.
    if current.ends_with(&secret) && current.len() > secret.len() {
        let boundary = current.len() - secret.len() - 1;
        if current.as_bytes()[boundary] == b'.' {
            return DomainMatch::ParentDomain;
        }
    }

    // Falling back to the registrable domain groups sibling subdomains
    // together. `psl` is what keeps this from matching all of `co.uk`.
    match (registrable_domain(&secret), registrable_domain(&current)) {
        (Some(a), Some(b)) if a == b => DomainMatch::RegistrableDomain,
        _ => DomainMatch::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_full_urls_to_bare_hosts() {
        let cases = [
            ("https://github.com/login", "github.com"),
            ("https://www.google.com", "google.com"),
            ("http://mail.google.com/u/0/#inbox", "mail.google.com"),
            ("https://GitHub.COM", "github.com"),
            ("github.com", "github.com"),
            ("https://example.com:8443/path", "example.com"),
            ("https://user:pass@example.com/x", "example.com"),
            ("https://example.com./", "example.com"),
            ("localhost:3000", "localhost"),
        ];
        for (input, want) in cases {
            assert_eq!(
                normalize_host(input).as_deref(),
                Some(want),
                "normalizing {input}"
            );
        }
    }

    #[test]
    fn non_web_urls_have_no_host() {
        for input in [
            "", "   ", "about:blank", "chrome://settings", "file:///home/u/x.txt",
            "data:text/html,hi", "javascript:void(0)",
        ] {
            assert_eq!(normalize_host(input), None, "input {input:?}");
        }
    }

    #[test]
    fn ipv6_literals_survive_normalization() {
        assert_eq!(
            normalize_host("http://[2001:db8::1]:8080/x").as_deref(),
            Some("[2001:db8::1]")
        );
    }

    #[test]
    fn registrable_domain_uses_the_public_suffix_list() {
        assert_eq!(registrable_domain("mail.google.com").as_deref(), Some("google.com"));
        assert_eq!(registrable_domain("google.com").as_deref(), Some("google.com"));
        // The case a naive "last two labels" rule gets wrong.
        assert_eq!(registrable_domain("bbc.co.uk").as_deref(), Some("bbc.co.uk"));
        assert_eq!(
            registrable_domain("news.bbc.co.uk").as_deref(),
            Some("bbc.co.uk")
        );
    }

    #[test]
    fn ip_literals_have_no_registrable_domain() {
        assert_eq!(registrable_domain("192.168.1.1"), None);
        assert_eq!(registrable_domain("[2001:db8::1]"), None);
    }

    #[test]
    fn identical_hosts_match_exactly() {
        assert_eq!(match_domain("github.com", "github.com"), DomainMatch::Exact);
        assert_eq!(
            match_domain("https://www.github.com/login", "github.com"),
            DomainMatch::Exact
        );
    }

    #[test]
    fn a_parent_domain_secret_matches_its_subdomain() {
        assert_eq!(
            match_domain("github.com", "api.github.com"),
            DomainMatch::ParentDomain
        );
    }

    #[test]
    fn sibling_subdomains_match_via_the_registrable_domain() {
        assert_eq!(
            match_domain("mail.google.com", "calendar.google.com"),
            DomainMatch::RegistrableDomain
        );
    }

    #[test]
    fn suffix_lookalikes_do_not_match() {
        // The attack this guards against: registering `notgithub.com` to
        // harvest a `github.com` credential from a naive suffix check.
        assert_eq!(match_domain("github.com", "notgithub.com"), DomainMatch::None);
        assert_eq!(match_domain("github.com", "github.com.evil.tld"), DomainMatch::None);
    }

    #[test]
    fn unrelated_sites_sharing_a_public_suffix_do_not_match() {
        // Both are under `co.uk`, but they are different registrable domains.
        assert_eq!(match_domain("bbc.co.uk", "hsbc.co.uk"), DomainMatch::None);
        assert_eq!(match_domain("google.com", "example.com"), DomainMatch::None);
    }

    #[test]
    fn empty_domains_never_match() {
        assert_eq!(match_domain("", "github.com"), DomainMatch::None);
        assert_eq!(match_domain("github.com", ""), DomainMatch::None);
    }

    #[test]
    fn match_strength_is_ordered() {
        assert!(DomainMatch::Exact > DomainMatch::ParentDomain);
        assert!(DomainMatch::ParentDomain > DomainMatch::RegistrableDomain);
        assert!(DomainMatch::RegistrableDomain > DomainMatch::None);
        assert!(!DomainMatch::None.is_match());
        assert!(DomainMatch::Exact.is_match());
    }
}
