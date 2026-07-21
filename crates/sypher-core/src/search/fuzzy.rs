//! Ranking secrets for the popup.
//!
//! Two inputs decide the order: the domain of whatever the user is looking at,
//! and whatever they have typed. Context beats typing. If the user is on
//! `github.com`, their GitHub credential should be preselected before they
//! touch the keyboard, and it should stay near the top even if they start
//! typing something that fuzzy-matches another entry slightly better.
//!
//! That is enforced structurally by [`Score`]'s field order rather than by
//! tuning weights: `domain` is compared first, and only ties fall through to
//! the fuzzy score. Weight tuning would eventually let a strong fuzzy match on
//! an unrelated entry outrank the site the user is actually on, which is the
//! one outcome that would make the popup untrustworthy.
//!
//! Only metadata is searched. The fuzzy matcher never sees a decrypted value,
//! which is what lets the list render before any unlock.

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher};

use crate::model::SecretMeta;
use crate::search::domain::{match_domain, DomainMatch};

/// A secret's ranking for one query, in comparison order.
///
/// Derived `Ord` compares fields top to bottom, which encodes the priority:
/// domain relevance, then fuzzy quality, then recency as a stable tiebreak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Score {
    /// How well the secret matches the active browser's host.
    pub domain: DomainMatch,
    /// Fuzzy match quality against the typed query. Zero when no query.
    pub fuzzy: u32,
    /// Last-updated timestamp, so equally relevant entries surface the one
    /// most recently used.
    pub recency: i64,
}

/// A secret paired with its score for the current query and context.
#[derive(Debug, Clone)]
pub struct Ranked {
    pub meta: SecretMeta,
    pub score: Score,
}

/// The context the popup was opened in.
#[derive(Debug, Clone, Default)]
pub struct SearchContext {
    /// Hostname of the focused browser tab, when known.
    pub host: Option<String>,
    /// Window class of the focused application, when known.
    pub application: Option<String>,
}

/// Ranks and filters secrets for display.
///
/// Owns a `Matcher`, which nucleo requires to be reused across calls (it holds
/// scratch allocations). One instance lives in the popup for the life of the
/// process.
pub struct Searcher {
    matcher: Matcher,
}

impl Default for Searcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Searcher {
    pub fn new() -> Self {
        Self {
            // The path-oriented config scores separator-delimited text like
            // `github.com` and `aws/prod/db` better than the default.
            matcher: Matcher::new(Config::DEFAULT.match_paths()),
        }
    }

    /// Ranks `secrets` for `query` in `ctx`, best first.
    ///
    /// With a non-empty query, entries that do not fuzzy-match at all are
    /// dropped. With an empty query, everything is kept and ordering is by
    /// context then recency, which is what makes the popup useful the instant
    /// it opens.
    ///
    /// When the context names a host and at least one secret matches it, the
    /// non-matching secrets are filtered out entirely rather than merely
    /// ranked lower. Showing 200 unrelated credentials under the one the user
    /// wants defeats the purpose of the filter. If nothing matches the host,
    /// everything is shown, since an empty popup is worse than an unfiltered
    /// one.
    pub fn rank(&mut self, secrets: &[SecretMeta], query: &str, ctx: &SearchContext) -> Vec<Ranked> {
        let query = query.trim();
        let pattern = (!query.is_empty()).then(|| {
            Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart)
        });

        let mut out: Vec<Ranked> = Vec::with_capacity(secrets.len());
        let mut buf = Vec::new();

        for meta in secrets {
            let domain = self.domain_score(meta, ctx);

            let fuzzy = match &pattern {
                None => 0,
                Some(p) => {
                    // Each haystack is scored separately and the best kept, so
                    // that typing a tag or a username finds the entry just as
                    // well as typing its name.
                    let mut best = None;
                    for field in Self::haystacks(meta) {
                        buf.clear();
                        let haystack = nucleo_matcher::Utf32Str::new(&field, &mut buf);
                        if let Some(s) = p.score(haystack, &mut self.matcher) {
                            best = Some(best.map_or(s, |b: u32| b.max(s)));
                        }
                    }
                    match best {
                        // No field matched the query at all: drop the entry.
                        None => continue,
                        Some(s) => s,
                    }
                }
            };

            out.push(Ranked {
                meta: meta.clone(),
                score: Score {
                    domain,
                    fuzzy,
                    recency: meta.updated_at,
                },
            });
        }

        if ctx.host.is_some() && out.iter().any(|r| r.score.domain.is_match()) {
            out.retain(|r| r.score.domain.is_match());
        }

        // Descending: highest score first.
        out.sort_by(|a, b| b.score.cmp(&a.score));
        out
    }

    /// Scores a secret against the active window's host and application.
    fn domain_score(&self, meta: &SecretMeta, ctx: &SearchContext) -> DomainMatch {
        if let Some(host) = &ctx.host {
            let m = match_domain(&meta.domain, host);
            if m.is_match() {
                return m;
            }
        }
        // An application-bound secret matches when the focused window class
        // corresponds. Treated as a registrable-domain-strength signal: real,
        // but weaker than an exact URL match.
        if let Some(app) = &ctx.application {
            if !meta.application.is_empty()
                && meta.application.eq_ignore_ascii_case(app.trim())
            {
                return DomainMatch::RegistrableDomain;
            }
        }
        DomainMatch::None
    }

    /// The metadata fields a query is matched against. Never includes the
    /// secret value, which is not in `SecretMeta` to begin with.
    fn haystacks(meta: &SecretMeta) -> Vec<String> {
        let mut fields = Vec::with_capacity(4 + meta.tags.len());
        fields.push(meta.name.clone());
        if !meta.domain.is_empty() {
            fields.push(meta.domain.clone());
        }
        if !meta.application.is_empty() {
            fields.push(meta.application.clone());
        }
        if !meta.username.is_empty() {
            fields.push(meta.username.clone());
        }
        fields.extend(meta.tags.iter().cloned());
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SecretType;

    fn secret(name: &str, domain: &str) -> SecretMeta {
        let mut m = SecretMeta::new(name, SecretType::Password);
        m.domain = domain.to_string();
        m
    }

    fn names(ranked: &[Ranked]) -> Vec<&str> {
        ranked.iter().map(|r| r.meta.name.as_str()).collect()
    }

    fn corpus() -> Vec<SecretMeta> {
        vec![
            secret("GitHub", "github.com"),
            secret("GitLab", "gitlab.com"),
            secret("Google Mail", "mail.google.com"),
            secret("Google Cloud", "console.cloud.google.com"),
            secret("AWS Console", "aws.amazon.com"),
        ]
    }

    #[test]
    fn empty_query_and_no_context_returns_everything() {
        let mut s = Searcher::new();
        let out = s.rank(&corpus(), "", &SearchContext::default());
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn host_context_filters_to_matching_secrets() {
        let mut s = Searcher::new();
        let ctx = SearchContext {
            host: Some("github.com".into()),
            ..Default::default()
        };
        let out = s.rank(&corpus(), "", &ctx);
        assert_eq!(names(&out), vec!["GitHub"]);
    }

    #[test]
    fn subdomains_of_the_same_site_are_grouped() {
        let mut s = Searcher::new();
        let ctx = SearchContext {
            host: Some("drive.google.com".into()),
            ..Default::default()
        };
        let out = s.rank(&corpus(), "", &ctx);
        assert_eq!(out.len(), 2, "both google.com secrets should show");
        assert!(names(&out).contains(&"Google Mail"));
    }

    #[test]
    fn an_unmatched_host_shows_everything_rather_than_nothing() {
        let mut s = Searcher::new();
        let ctx = SearchContext {
            host: Some("stackoverflow.com".into()),
            ..Default::default()
        };
        let out = s.rank(&corpus(), "", &ctx);
        assert_eq!(out.len(), 5, "an empty popup is worse than an unfiltered one");
    }

    #[test]
    fn exact_host_outranks_a_sibling_subdomain() {
        let mut s = Searcher::new();
        let ctx = SearchContext {
            host: Some("mail.google.com".into()),
            ..Default::default()
        };
        let out = s.rank(&corpus(), "", &ctx);
        assert_eq!(out[0].meta.name, "Google Mail");
        assert_eq!(out[0].score.domain, DomainMatch::Exact);
    }

    #[test]
    fn query_filters_out_non_matching_entries() {
        let mut s = Searcher::new();
        let out = s.rank(&corpus(), "gitlab", &SearchContext::default());
        assert_eq!(names(&out), vec!["GitLab"]);
    }

    #[test]
    fn query_matches_are_fuzzy_not_exact() {
        let mut s = Searcher::new();
        let out = s.rank(&corpus(), "ghb", &SearchContext::default());
        assert!(names(&out).contains(&"GitHub"), "got {:?}", names(&out));
    }

    #[test]
    fn query_matches_tags_and_usernames_too() {
        let mut corpus = corpus();
        corpus[0].tags = vec!["work".into()];
        corpus[1].username = "octodev".into();

        let mut s = Searcher::new();
        assert_eq!(
            names(&s.rank(&corpus, "work", &SearchContext::default())),
            vec!["GitHub"]
        );
        assert_eq!(
            names(&s.rank(&corpus, "octodev", &SearchContext::default())),
            vec!["GitLab"]
        );
    }

    #[test]
    fn nonsense_query_returns_nothing() {
        let mut s = Searcher::new();
        let out = s.rank(&corpus(), "zzzqqqxxx", &SearchContext::default());
        assert!(out.is_empty());
    }

    #[test]
    fn domain_context_outranks_a_better_fuzzy_match() {
        // The property the Score field order exists to guarantee: being on
        // github.com must keep GitHub first even when the query also fuzzy
        // matches GitLab.
        let mut s = Searcher::new();
        let ctx = SearchContext {
            host: Some("github.com".into()),
            ..Default::default()
        };
        let out = s.rank(&corpus(), "git", &ctx);
        assert_eq!(out[0].meta.name, "GitHub");
    }

    #[test]
    fn application_context_matches_a_desktop_secret() {
        let mut corpus = corpus();
        let mut slack = SecretMeta::new("Slack", SecretType::Password);
        slack.application = "slack".into();
        corpus.push(slack);

        let mut s = Searcher::new();
        let ctx = SearchContext {
            application: Some("Slack".into()),
            ..Default::default()
        };
        let out = s.rank(&corpus, "", &ctx);
        assert_eq!(out[0].meta.name, "Slack", "window class match is case insensitive");
    }

    #[test]
    fn recency_breaks_ties() {
        let mut a = secret("Alpha", "example.com");
        a.updated_at = 100;
        let mut b = secret("Alpha", "example.com");
        b.updated_at = 900;

        let mut s = Searcher::new();
        let out = s.rank(&[a, b.clone()], "", &SearchContext::default());
        assert_eq!(out[0].meta.id, b.id, "most recently updated should win");
    }

    #[test]
    fn whitespace_query_behaves_like_an_empty_one() {
        let mut s = Searcher::new();
        let out = s.rank(&corpus(), "   ", &SearchContext::default());
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn ranking_an_empty_vault_is_not_an_error() {
        let mut s = Searcher::new();
        let ctx = SearchContext {
            host: Some("github.com".into()),
            ..Default::default()
        };
        assert!(s.rank(&[], "anything", &ctx).is_empty());
    }
}
