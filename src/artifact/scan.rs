//! Reading a Callback artifact well enough to serve it: the one data slot
//! this bridge substitutes into, the mount point the artifact contract
//! requires, and the modules the browser executes.
//!
//! The artifact carries the semantic equivalent of the contract's example, so
//! a script element is read by its attributes rather than their spelling. The
//! elements are found by their bytes and not by the element that encloses
//! them: a document burying them in an inert one is read as carrying them. The artifact arrives with
//! the hashes of those modules in its own `script-src`; this bridge checks
//! them against the code and carries them into the policy it composes. The
//! data slot is not executable, so substituting into it leaves every hashed
//! byte where it was.

use std::ops::Range;

/// The marker the build leaves for deployment data, and the element that
/// carries it. Both are fixed by the artifact contract.
pub(crate) const MARKER: &str = "__LIBID_CALLBACK_CONFIG__";
const SLOT_ID: &str = "libid-callback-config";
const SLOT_TYPE: &str = "application/json";
const MODULE_TYPE: &str = "module";
const SCRIPT_OPEN: &str = "<script";
const SCRIPT_CLOSE: &str = "</script>";

/// The element the Callback renders into, which the artifact carries once.
const MOUNT_POINT: &str = "<main id=\"libid-root\"></main>";

/// The largest artifact this bridge will read. The retrieval stops at it,
/// which is the one place the bytes arrive.
pub(crate) const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// The most script hashes an artifact's policy may name.
const MAX_HASHES: usize = 8;

/// Why an artifact was refused. Every variant is a refusal to serve, never a
/// repair.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ArtifactError {
    #[error("the document carries {0} configuration slots, and must carry one")]
    Slots(usize),
    #[error("a script at byte {0} is neither the configuration slot nor a plain module")]
    UnreadableScript(usize),
    #[error("the document carries {0} modules, and must carry 1 to {MAX_HASHES}")]
    Modules(usize),
    #[error("the artifact's policy names hashes that are not its code's")]
    Hashes,
    #[error("the configuration slot does not hold exactly the marker")]
    Marker,
    #[error("the document does not carry exactly one empty `<main id=\"libid-root\">`")]
    MountPoint,
    #[error("the artifact's own policy {0}")]
    UpstreamPolicy(String),
    #[error("the composed policy is not a header value: {0}")]
    Policy(String),
}

/// What the document carries: the slot the deployment data replaces, and the
/// modules the browser executes.
#[derive(Debug)]
pub(crate) struct Layout {
    /// The byte range of what the one data slot holds.
    pub(crate) slot: Range<usize>,
    /// The text of each module, in document order: the span a CSP hash covers.
    pub(crate) modules: Vec<Range<usize>>,
}

/// What a script element is, by what its attributes say.
enum Script {
    /// The data slot: the deployment's data goes between its tags.
    Slot,
    /// A module: its text is what the browser executes, and what a hash
    /// covers.
    Module,
}

/// Read an artifact, or refuse it.
///
/// Every script element is the data slot or a plain module, and the text of
/// each is taken between its tags. A document writing `<script` anywhere a
/// script element may not begin is refused rather than read: the artifact is
/// one page this bridge and the Distribution both know the shape of.
pub(crate) fn read(html: &str) -> Result<Layout, ArtifactError> {
    let mut slot = None;
    let mut modules = Vec::new();
    let mut at = 0;
    while let Some(k) = html[at..].find(SCRIPT_OPEN) {
        let open = at + k;
        let (kind, tag_end) = script(html, open)?;
        let end = html[tag_end..]
            .find(SCRIPT_CLOSE)
            .map(|k| tag_end + k)
            .ok_or(ArtifactError::UnreadableScript(open))?;
        match kind {
            Script::Slot if slot.is_some() => return Err(ArtifactError::Slots(2)),
            Script::Slot => slot = Some(tag_end..end),
            Script::Module => modules.push(tag_end..end),
        }
        at = end + SCRIPT_CLOSE.len();
    }

    let Some(slot) = slot else {
        return Err(ArtifactError::Slots(0));
    };
    if modules.is_empty() || modules.len() > MAX_HASHES {
        return Err(ArtifactError::Modules(modules.len()));
    }
    if html.matches(MOUNT_POINT).count() != 1 {
        return Err(ArtifactError::MountPoint);
    }
    Ok(Layout { slot, modules })
}

/// What the script element opening at `open` is, and where its tag ends.
///
/// The attributes are read in whatever order and quoting the build wrote
/// them. A script this bridge cannot hash or substitute into -- one carrying
/// a `src`, or a type it does not read -- is refused.
fn script(html: &str, open: usize) -> Result<(Script, usize), ArtifactError> {
    let refuse = || ArtifactError::UnreadableScript(open);
    let (attributes, tag_end) = attributes(html, open + SCRIPT_OPEN.len())?;
    let value = |wanted: &str| {
        attributes
            .iter()
            .find(|(name, _)| name == wanted)
            .map(|(_, value)| value.as_str())
    };
    if value("src").is_some() {
        return Err(refuse());
    }
    let kind = match value("type").ok_or_else(refuse)? {
        t if t.eq_ignore_ascii_case(SLOT_TYPE) && value("id") == Some(SLOT_ID) => {
            Script::Slot
        }
        t if t.eq_ignore_ascii_case(MODULE_TYPE) => Script::Module,
        _ => return Err(refuse()),
    };
    Ok((kind, tag_end))
}

/// The attributes of a tag whose name ends at `from`, lowercased by name, and
/// the byte after its `>`.
fn attributes(
    html: &str,
    from: usize,
) -> Result<(Vec<(String, String)>, usize), ArtifactError> {
    let refuse = || ArtifactError::UnreadableScript(from);
    let bytes = html.as_bytes();
    let mut attributes = Vec::new();
    let mut i = from;
    loop {
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        match bytes.get(i) {
            Some(b'>') => return Ok((attributes, i + 1)),
            Some(_) => {}
            None => return Err(refuse()),
        }
        let name_start = i;
        while bytes
            .get(i)
            .is_some_and(|b| !b.is_ascii_whitespace() && !b"=>/".contains(b))
        {
            i += 1;
        }
        if i == name_start {
            return Err(refuse());
        }
        let name = html[name_start..i].to_ascii_lowercase();
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if bytes.get(i) != Some(&b'=') {
            attributes.push((name, String::new()));
            continue;
        }
        i += 1;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        let value = match bytes.get(i) {
            Some(quote @ (b'"' | b'\'')) => {
                let quote = *quote;
                i += 1;
                let start = i;
                while bytes.get(i).is_some_and(|b| *b != quote) {
                    i += 1;
                }
                if bytes.get(i).is_none() {
                    return Err(refuse());
                }
                let value = &html[start..i];
                i += 1;
                value
            }
            Some(_) => {
                let start = i;
                while bytes
                    .get(i)
                    .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'>')
                {
                    i += 1;
                }
                &html[start..i]
            }
            None => return Err(refuse()),
        };
        attributes.push((name, value.to_owned()));
    }
}

/// The script hashes an artifact's own policy names.
///
/// The artifact is served with the hashes of the code it carries. A
/// `script-src` naming anything but hashes is refused here, and
/// [`CallbackDocument::compose`](super::CallbackDocument::compose) checks
/// what it names against the code before either reaches a browser.
pub(crate) fn script_hashes(policy: &str) -> Result<Vec<String>, ArtifactError> {
    let refuse = |why: String| Err(ArtifactError::UpstreamPolicy(why));

    let Some(directive) = policy.split(';').find(|d| {
        d.split_whitespace()
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("script-src"))
    }) else {
        return refuse("names no script-src".into());
    };

    let hashes: Vec<String> = directive
        .split_whitespace()
        .skip(1)
        .map(str::to_owned)
        .collect();
    if hashes.is_empty() {
        return refuse("names a script-src with no source".into());
    }
    if hashes.len() > MAX_HASHES {
        return refuse(format!(
            "names {} script sources, and at most {MAX_HASHES} are read",
            hashes.len()
        ));
    }
    if let Some(source) = hashes.iter().find(|s| !is_hash(s)) {
        return refuse(format!("names the script source {source}, and not a hash"));
    }
    Ok(hashes)
}

/// Whether `source` is a CSP hash source expression: `'sha256-…'` and the two
/// longer digests, base64 between the quotes.
fn is_hash(source: &str) -> bool {
    let Some(rest) = ["'sha256-", "'sha384-", "'sha512-"]
        .into_iter()
        .find_map(|prefix| source.strip_prefix(prefix))
    else {
        return false;
    };
    let Some(digest) = rest.strip_suffix('\'') else {
        return false;
    };
    !digest.is_empty()
        && digest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=-_".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document as the Distribution builds one: the slot, the mount point,
    /// and `body` after them.
    fn doc(body: &str) -> String {
        format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">\
             <title>libID</title><body><main id=\"libid-root\"></main>\
             <script id=\"libid-callback-config\" type=\"application/json\">\
             {MARKER}</script>{body}</body></html>"
        )
    }

    fn module(code: &str) -> String {
        doc(&format!("<script type=\"module\">{code}</script>"))
    }

    /// The slot is what its element holds, and the module is its text
    /// exactly: the span a CSP hash covers.
    #[test]
    fn the_slot_and_the_modules_are_what_their_elements_hold() {
        let html = module("let x = 1;");
        let layout = read(&html).expect("a document this bridge reads");
        assert_eq!(html[layout.slot].trim(), MARKER);
        assert_eq!(layout.modules.len(), 1);
        assert_eq!(&html[layout.modules[0].clone()], "let x = 1;");
    }

    /// A document may carry more than one module, and the order is the
    /// document's.
    #[test]
    fn every_module_is_read_in_document_order() {
        let html = doc("<script type=\"module\">first;</script>\
             <p>between</p><script type=\"module\">second;</script>");
        let layout = read(&html).expect("two modules");
        let text: Vec<&str> = layout.modules.iter().map(|r| &html[r.clone()]).collect();
        assert_eq!(text, ["first;", "second;"]);
    }

    /// The artifact carries the semantic equivalent of the contract's
    /// example, so the order, the quoting and the case of a script element's
    /// attributes are the build's to choose.
    #[test]
    fn a_script_element_is_read_by_its_attributes() {
        for spelling in [
            "<script type=\"application/json\" id=\"libid-callback-config\">",
            "<script id='libid-callback-config' type='application/json'>",
            "<script  id=libid-callback-config  TYPE=application/json >",
            "<script\nid=\"libid-callback-config\"\ntype=\"APPLICATION/JSON\">",
        ] {
            let html = format!(
                "<!doctype html><body><main id=\"libid-root\"></main>\
                 {spelling}{MARKER}</script>\
                 <script type='module'>let x = 1;</script></body>"
            );
            let layout =
                read(&html).unwrap_or_else(|e| panic!("refused {spelling}: {e}"));
            assert_eq!(html[layout.slot].trim(), MARKER);
            assert_eq!(&html[layout.modules[0].clone()], "let x = 1;");
        }
    }

    /// A script this bridge can neither hash nor substitute into is refused.
    #[test]
    fn a_script_this_bridge_does_not_read_is_refused() {
        for script in [
            "<script src=\"/app.js\" type=\"module\"></script>",
            "<script>let x = 1;</script>",
            "<script type=\"text/javascript\">let x = 1;</script>",
            "<script type=\"application/json\">{}</script>",
            "<script id=\"other\" type=\"application/json\">{}</script>",
            "<script type=\"module\"",
        ] {
            let html = format!(
                "<!doctype html><body><main id=\"libid-root\"></main>\
                 <script id=\"libid-callback-config\" type=\"application/json\">\
                 {MARKER}</script>\
                 <script type=\"module\">let x = 1;</script>{script}</body>"
            );
            assert!(read(&html).is_err(), "{script} must be refused");
        }
    }

    /// The fixture the tests serve is one this bridge reads.
    #[test]
    fn the_fixture_is_readable() {
        let html = crate::fixtures::ARTIFACT;
        let layout = read(html).expect("the fixture artifact");
        assert_eq!(html[layout.slot].trim(), MARKER);
        assert_eq!(layout.modules.len(), 1);
    }

    /// Each of these is refused.
    #[test]
    fn a_document_this_bridge_cannot_serve_is_refused() {
        let slot_element = format!(
            "<script id=\"libid-callback-config\" type=\"application/json\">\
             {MARKER}</script>"
        );
        let code = "<script type=\"module\">let x = 1;</script>";
        for (why, html) in [
            (
                "no slot",
                format!("<body><main id=\"libid-root\"></main>{code}</body>"),
            ),
            ("two slots", doc(&format!("{slot_element}{code}"))),
            (
                "no mount point",
                format!("<body>{slot_element}{code}</body>"),
            ),
            (
                "two mount points",
                doc(&format!("<main id=\"libid-root\"></main>{code}")),
            ),
            ("no module", doc("<p>nothing to run</p>")),
            (
                "a script that is neither",
                doc("<script src=\"/app.js\"></script>"),
            ),
            (
                "a module that never closes",
                doc("<script type=\"module\">let x = 1;"),
            ),
        ] {
            assert!(read(&html).is_err(), "{why} must be refused");
        }
    }

    /// The hashes are read out of the artifact's own `script-src`, whatever
    /// the rest of its policy says.
    #[test]
    fn the_hashes_are_the_ones_the_artifact_declares() {
        let policy = "default-src 'none'; SCRIPT-SRC 'sha256-abc123+/=' 'sha384-def'; \
                      style-src 'unsafe-inline'";
        assert_eq!(
            script_hashes(policy).expect("a hash-only script-src"),
            ["'sha256-abc123+/='", "'sha384-def'"]
        );
    }

    /// A policy naming anything but hashes is refused, so no source this
    /// bridge did not write reaches the composed policy.
    #[test]
    fn a_policy_that_is_not_hash_only_is_refused() {
        for policy in [
            "default-src 'none'",
            "script-src",
            "script-src 'unsafe-inline'",
            "script-src 'self'",
            "script-src https://cdn.example",
            "script-src 'nonce-abc'",
            "script-src 'strict-dynamic' 'sha256-abc'",
            "script-src 'sha256-'",
            "script-src sha256-abc",
            "script-src 'sha1-abc'",
            "script-src 'sha256-a b'",
            "script-src 'sha256-a' 'sha256-b' 'sha256-c' 'sha256-d' 'sha256-e' \
             'sha256-f' 'sha256-g' 'sha256-h' 'sha256-i'",
        ] {
            assert!(
                matches!(script_hashes(policy), Err(ArtifactError::UpstreamPolicy(_))),
                "{policy} must be refused"
            );
        }
    }
}
