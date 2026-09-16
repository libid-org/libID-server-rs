//! The callback document this bridge serves: the CCDP Distribution's artifact
//! with one unversioned list substituted into its one non-executable slot,
//! under a Content-Security-Policy composed here from this deployment's own
//! sources and the script hashes the artifact arrived with, checked against
//! the code they cover.

pub(crate) mod scan;
pub(crate) mod upstream;

use axum::http::HeaderValue;
use base64::{
    engine::general_purpose::STANDARD,
    Engine,
};
use bytes::Bytes;
use sha2::{
    Digest,
    Sha256,
};

use scan::ArtifactError;
use upstream::Upstream;

use crate::{
    error::Error,
    origin::Origin,
};

#[cfg(test)]
pub(crate) use crate::fixtures::ARTIFACT as FIXTURE;

/// What the deployment contributes to the document and its policy.
pub(crate) struct DeploymentInputs<'a> {
    /// The CCDP Distribution this bridge selects: in the inserted list, and
    /// the one origin the policy admits a frame from.
    pub(crate) ccdp_origin: &'a Origin,
    /// The effective admission set, which the Callback authenticates an
    /// application against. It contains the CCDP origin.
    pub(crate) allowed_origins: &'a [Origin],
}

/// The finished document: the exact bytes, and the policy they are served
/// under.
pub(crate) struct CallbackDocument {
    /// The document, composed once.
    pub(crate) body: Bytes,
    /// Its `Content-Security-Policy`, naming the script hashes the artifact
    /// arrived with.
    pub(crate) csp: HeaderValue,
}

impl CallbackDocument {
    /// Configure one artifact and compose the response it is served as: the
    /// one constructor, where the deployment's data goes in and the policy is
    /// written.
    ///
    /// `hashes` are the script sources the artifact's own policy named. They
    /// must be the hashes of the modules the document carries: a Distribution
    /// that ships a stale one is refused here rather than serving a document
    /// whose code the browser blocks. The slot is not executable and is the
    /// only thing substitution touches, so every byte those hashes cover is
    /// served unchanged.
    pub(crate) fn compose(
        html: &str,
        hashes: &[String],
        inputs: &DeploymentInputs<'_>,
    ) -> Result<CallbackDocument, ArtifactError> {
        let layout = scan::read(html)?;
        // The slot holds exactly the marker, and the marker occurs nowhere
        // else.
        if html[layout.slot.clone()].trim() != scan::MARKER
            || html.matches(scan::MARKER).nth(1).is_some()
        {
            return Err(ArtifactError::Marker);
        }
        // What the artifact's policy names is what its code hashes to.
        let mut declared: Vec<&str> = hashes.iter().map(String::as_str).collect();
        let mut carried: Vec<String> = layout
            .modules
            .iter()
            .map(|r| hash_source(&html[r.clone()]))
            .collect();
        declared.sort_unstable();
        carried.sort_unstable();
        if declared != carried {
            return Err(ArtifactError::Hashes);
        }

        // One unversioned list: `[allowedOrigins, ccdpOrigin]`.
        let record = serde_json::json!([inputs.allowed_origins, inputs.ccdp_origin]);
        let mut body = String::with_capacity(html.len());
        body.push_str(&html[..layout.slot.start]);
        body.push_str(&json(&record));
        body.push_str(&html[layout.slot.end..]);
        // The composed document carries the same one slot and mount point.
        scan::read(&body)?;

        let csp = policy(hashes, inputs.ccdp_origin.as_str());
        let csp = HeaderValue::from_str(&csp)
            .map_err(|e| ArtifactError::Policy(format!("{csp:?}: {e}")))?;
        Ok(CallbackDocument {
            body: Bytes::from(body),
            csp,
        })
    }
}

/// A composed document and the validator it was retrieved under.
///
/// One value, published as one unit, and that is the point: the ETag advances
/// only where a document does. A `200` whose body this bridge refuses publishes
/// nothing, so the next revalidation cannot send `If-None-Match` for a document
/// that was never served -- which would turn one bad artifact into a permanent
/// `304` for a document nobody has.
pub(crate) struct Published {
    /// The document, and the policy it is served under.
    pub(crate) document: CallbackDocument,
    /// The `ETag` the document arrived with, sent back as `If-None-Match`.
    pub(crate) etag: Option<String>,
}

impl Published {
    /// The artifact retrieved from `upstream` by a request carrying no
    /// validator, composed for the deployment. A retrieval that fails is an
    /// error, and the process does not start.
    pub(crate) async fn retrieved(
        upstream: &Upstream,
        allowed_origins: &[Origin],
    ) -> Result<Published, Error> {
        let url = upstream.url();
        let published = upstream
            .retrieve(allowed_origins, None)
            .await
            .map_err(|e| Error::ArtifactUnavailable {
                url: url.clone(),
                detail: format!("{e}"),
            })?
            .ok_or_else(|| Error::ArtifactUnavailable {
                url: url.clone(),
                detail: upstream::FetchError::UnaskedNotModified.to_string(),
            })?;
        published.log(&url, "retrieved the callback artifact");
        Ok(published)
    }

    /// One log line naming the document: its URL, validator and policy.
    pub(crate) fn log(&self, url: &str, event: &str) {
        tracing::info!(
            url,
            etag = self.etag.as_deref().unwrap_or("<none>"),
            policy = self.document.csp.to_str().unwrap_or("<unreadable>"),
            "{event}"
        );
    }
}

/// The response policy: this deployment's own sources, and the script hashes
/// the artifact arrived with.
fn policy(hashes: &[String], ccdp_origin: &str) -> String {
    [
        "default-src 'none'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "form-action 'none'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
        // Hashes only; the artifact bundles its dependencies.
        format!("script-src {}", hashes.join(" ")),
        // The artifact's own inline styles.
        "style-src 'unsafe-inline'".to_owned(),
        // Callback may frame the Distribution it came from, and nothing else.
        format!("frame-src {ccdp_origin}"),
        "connect-src 'none'".to_owned(),
    ]
    .join("; ")
}

/// The CSP source for an inline script: the base64 SHA-256 of its exact text.
fn hash_source(script: &str) -> String {
    format!(
        "'sha256-{}'",
        STANDARD.encode(Sha256::digest(script.as_bytes()))
    )
}

/// A JSON island, escaped so it cannot end the script element that carries
/// it: `<`, `>`, `&`, the line separators and every non-ASCII character leave
/// as `\uXXXX` escapes, so the inserted data is ASCII.
fn json(value: &serde_json::Value) -> String {
    use std::fmt::Write as _;

    let rendered = value.to_string();
    let mut out = String::with_capacity(rendered.len());
    for c in rendered.chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(spelling: &str) -> Origin {
        Origin::parse("T", spelling).unwrap()
    }

    /// The effective admission set: the application origins with the CCDP
    /// origin joined.
    fn origins() -> Vec<Origin> {
        vec![
            origin("https://app.example"),
            origin("https://ccdp.example"),
        ]
    }

    /// The hashes a Distribution serves the fixture with.
    fn hashes() -> Vec<String> {
        crate::fixtures::artifact_hashes()
    }

    fn composed(html: &str, origins: &[Origin]) -> CallbackDocument {
        CallbackDocument::compose(
            html,
            &hashes(),
            &DeploymentInputs {
                ccdp_origin: &origin("https://ccdp.example"),
                allowed_origins: origins,
            },
        )
        .expect("composes")
    }

    fn text(doc: &CallbackDocument) -> String {
        String::from_utf8(doc.body.to_vec()).unwrap()
    }

    /// The fixture composes.
    #[test]
    fn the_fixture_composes() {
        let doc = composed(FIXTURE, &origins());
        assert!(text(&doc).contains("https://app.example"));
    }

    /// The policy names the hashes the artifact arrived with, and no other
    /// script source.
    #[test]
    fn the_policy_names_the_hashes_the_artifact_declared() {
        let doc = composed(FIXTURE, &origins());
        let csp = doc.csp.to_str().unwrap();
        let script_src = csp
            .split("; ")
            .find(|d| d.starts_with("script-src "))
            .expect("a script-src");
        assert_eq!(
            script_src,
            format!("script-src {}", hashes().join(" ")),
            "the policy carries the artifact's hashes and nothing else"
        );
    }

    /// The inserted record is one unversioned list: the allowlist, then the
    /// origin.
    #[test]
    fn the_inserted_record_is_one_unversioned_list() {
        let doc = composed(FIXTURE, &origins());
        let html = text(&doc);
        let open = "<script id=\"libid-callback-config\" type=\"application/json\">";
        let start = html.find(open).unwrap() + open.len();
        let end = start + html[start..].find("</script>").unwrap();
        assert_eq!(
            &html[start..end],
            r#"[["https://app.example","https://ccdp.example"],"https://ccdp.example"]"#
        );
        assert!(!html.contains(scan::MARKER), "the marker is consumed");
    }

    /// Two insertions produce two documents with one `script-src`.
    #[test]
    fn substitution_does_not_move_the_bytes_the_browser_executes() {
        let one = composed(FIXTURE, &origins());
        let many = composed(
            FIXTURE,
            &[origin("https://a.example"), origin("https://b.example")],
        );
        assert_ne!(text(&one), text(&many));
        let script_src = |d: &CallbackDocument| {
            d.csp
                .to_str()
                .unwrap()
                .split("; ")
                .find(|x| x.starts_with("script-src "))
                .unwrap()
                .to_owned()
        };
        assert_eq!(script_src(&one), script_src(&many));
    }

    /// Every non-ASCII character leaves as a `\uXXXX` escape, astral planes as
    /// a surrogate pair.
    #[test]
    fn the_inserted_data_is_always_ascii() {
        let escaped = json(&serde_json::json!("caf\u{e9} \u{1f512} \u{2028} <&>"));
        assert!(escaped.is_ascii(), "{escaped}");
        assert!(escaped.contains("\\u00e9"), "{escaped}");
        assert!(
            escaped.contains("\\ud83d") && escaped.contains("\\udd12"),
            "{escaped}"
        );
        assert!(escaped.contains("\\u2028"), "{escaped}");
        for e in ["\\u003c", "\\u0026", "\\u003e"] {
            assert!(escaped.contains(e), "{e} missing from {escaped}");
        }
    }

    /// An inserted value cannot end the script element that carries it.
    #[test]
    fn an_inserted_value_cannot_end_the_script_element() {
        let hostile = json(&serde_json::json!(["https://a.example/</script><script>x"]));
        assert!(!hostile.contains("</script>"), "{hostile}");
        assert!(!hostile.contains("<script"), "{hostile}");
    }

    /// A policy naming a hash that is not the code's is refused: the browser
    /// would block that code, and the deployment would serve a blank page.
    #[test]
    fn an_artifact_whose_declared_hash_is_not_its_codes_is_refused() {
        let stale = vec!["'sha256-ZnJvbSBhbiBvbGRlciBidWlsZA=='".to_owned()];
        assert!(matches!(
            CallbackDocument::compose(
                FIXTURE,
                &stale,
                &DeploymentInputs {
                    ccdp_origin: &origin("https://ccdp.example"),
                    allowed_origins: &origins(),
                },
            ),
            Err(scan::ArtifactError::Hashes)
        ));

        // The same artifact under the hashes it was built with composes.
        assert!(composed(FIXTURE, &origins()).csp.to_str().is_ok());
    }

    /// A slot holding anything but the marker, or a marker occurring twice, is
    /// refused.
    #[test]
    fn a_slot_that_does_not_hold_exactly_the_marker_is_refused() {
        let filled = FIXTURE.replace(scan::MARKER, "[]");
        assert!(matches!(
            CallbackDocument::compose(
                &filled,
                &hashes(),
                &DeploymentInputs {
                    ccdp_origin: &origin("https://ccdp.example"),
                    allowed_origins: &origins(),
                },
            ),
            Err(scan::ArtifactError::Marker)
        ));

        let twice = FIXTURE.replace(
            "const query =",
            &format!("// {}\nconst query =", scan::MARKER),
        );
        assert!(matches!(
            CallbackDocument::compose(
                &twice,
                &hashes(),
                &DeploymentInputs {
                    ccdp_origin: &origin("https://ccdp.example"),
                    allowed_origins: &origins(),
                },
            ),
            Err(scan::ArtifactError::Marker)
        ));
    }
}
