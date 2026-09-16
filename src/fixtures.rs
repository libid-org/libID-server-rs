//! What the tests build a deployment from: a Distribution on loopback serving
//! the fixture artifact, and a configuration naming it. Compiled for the
//! crate's own tests and, under the `fixtures` feature, for the integration
//! tests.

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        LazyLock,
        Mutex,
        OnceLock,
    },
};

use axum::{
    extract::State,
    response::IntoResponse,
    routing::get,
    Router,
};
use hyper::{
    header,
    HeaderMap,
    StatusCode,
};

use crate::{
    artifact::upstream::ARTIFACT_PATH,
    config,
    state::AppState,
};

/// The fixture artifact: one configuration slot, one executable module, one
/// mount point.
pub const ARTIFACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/callback.html"
));

/// The runtime shared fixtures are served on. `#[tokio::test]` drops each
/// test's runtime, and every task on it, when the test returns; this one is
/// never dropped.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a runtime for the shared fixtures")
    });
    &RUNTIME
}

/// The script hashes the fixture artifact is served with: what a Distribution
/// computes over the code it ships, and what the bridge carries into the
/// policy it composes.
pub fn artifact_hashes() -> Vec<String> {
    use base64::Engine as _;
    use sha2::Digest as _;

    const OPEN: &str = "<script type=\"module\">";
    let start = ARTIFACT.find(OPEN).expect("the fixture carries one module") + OPEN.len();
    let end = start + ARTIFACT[start..].find("</script>").expect("it closes");
    let digest = sha2::Sha256::digest(&ARTIFACT.as_bytes()[start..end]);
    vec![format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )]
}

/// The `Content-Security-Policy` a Distribution serves the fixture artifact
/// under: hash-only, as the artifact contract requires.
pub fn artifact_policy() -> String {
    format!(
        "default-src 'none'; script-src {}; style-src 'unsafe-inline'",
        artifact_hashes().join(" ")
    )
}

/// What the fixture Distribution answers with next.
#[derive(Clone)]
pub struct Reply {
    /// The status line.
    pub status: StatusCode,
    /// The `Content-Type`.
    pub media: &'static str,
    /// The `ETag`, when it sends one.
    pub etag: Option<&'static str>,
    /// The body.
    pub body: String,
    /// A `Content-Encoding` to claim, for a Distribution that ignores what
    /// the request admitted.
    pub encoding: Option<&'static str>,
    /// Send the body with no `content-length`, as a chunked answer does.
    pub chunked: bool,
    /// The `Content-Security-Policy` it is served under, which names the
    /// hashes of the code it carries. `None` sends none.
    pub policy: Option<String>,
}

impl Reply {
    /// The artifact, as a healthy Distribution serves it.
    pub fn artifact() -> Reply {
        Reply {
            status: StatusCode::OK,
            media: "text/html; charset=utf-8",
            etag: Some("W/\"the-artifact\""),
            body: ARTIFACT.to_owned(),
            encoding: None,
            chunked: false,
            policy: Some(artifact_policy()),
        }
    }

    /// The same artifact under a new validator.
    pub fn replacement() -> Reply {
        Reply {
            etag: Some("W/\"the-replacement\""),
            ..Reply::artifact()
        }
    }
}

/// What the fixture has been told to say, and what it has been asked.
#[derive(Clone)]
struct Answers {
    /// Every request the fixture saw, in order.
    seen: Arc<Mutex<Vec<HeaderMap>>>,
    /// What it answers when nothing is queued.
    standing: Arc<Mutex<Reply>>,
    /// Answers for the next requests, ahead of the standing one.
    queued: Arc<Mutex<VecDeque<Reply>>>,
}

/// A Distribution, on loopback and in plaintext, served on [`runtime`].
pub struct Distribution {
    origin: String,
    answers: Answers,
}

impl Distribution {
    /// A Distribution answering with `reply`.
    pub async fn serving(reply: Reply) -> Distribution {
        let answers = Answers {
            seen: Arc::default(),
            standing: Arc::new(Mutex::new(reply)),
            queued: Arc::default(),
        };
        let router = Router::new()
            .route(ARTIFACT_PATH, get(answer))
            .with_state(answers.clone());
        let (bound, address) = tokio::sync::oneshot::channel();
        runtime().spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _ = bound.send(listener.local_addr().unwrap());
            let _ = axum::serve(listener, router).await;
        });
        let origin = format!("http://{}", address.await.unwrap());
        Distribution { origin, answers }
    }

    /// A Distribution serving the artifact.
    pub async fn healthy() -> Distribution {
        Distribution::serving(Reply::artifact()).await
    }

    /// Where it is, as a deployment's `--ccdp-origin`.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Answer every request from now on with this.
    pub fn now_serves(&self, reply: Reply) {
        *self.answers.standing.lock().unwrap() = reply;
    }

    /// Answer the next request with this, once.
    pub fn answers_next(&self, reply: Reply) {
        self.answers.queued.lock().unwrap().push_back(reply);
    }

    /// How many queued answers are still waiting to be given.
    pub fn still_queued(&self) -> usize {
        self.answers.queued.lock().unwrap().len()
    }

    /// Every request seen so far, in order.
    pub fn requests(&self) -> Vec<HeaderMap> {
        self.answers.seen.lock().unwrap().clone()
    }
}

async fn answer(
    State(answers): State<Answers>,
    headers: HeaderMap,
) -> axum::response::Response {
    answers.seen.lock().unwrap().push(headers.clone());
    let reply = match answers.queued.lock().unwrap().pop_front() {
        Some(queued) => queued,
        None => answers.standing.lock().unwrap().clone(),
    };
    // Only a `200` revalidates into a `304`.
    let asked = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if reply.status == StatusCode::OK && reply.etag.is_some() && asked == reply.etag {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let mut response = axum::response::Response::builder()
        .status(reply.status)
        .header(header::CONTENT_TYPE, reply.media);
    if let Some(etag) = reply.etag {
        response = response.header(header::ETAG, etag);
    }
    if let Some(encoding) = reply.encoding {
        response = response.header(header::CONTENT_ENCODING, encoding);
    }
    if let Some(policy) = &reply.policy {
        response = response.header(header::CONTENT_SECURITY_POLICY, policy);
    }
    let body = if reply.chunked {
        axum::body::Body::from_stream(futures_util::stream::iter([Ok::<_, String>(
            bytes::Bytes::from(reply.body),
        )]))
    } else {
        axum::body::Body::from(reply.body)
    };
    response.body(body).unwrap().into_response()
}

impl Distribution {
    /// One healthy Distribution, started once and shared by every test that
    /// builds a deployment.
    pub fn shared() -> &'static Distribution {
        static SHARED: OnceLock<Distribution> = OnceLock::new();
        SHARED.get_or_init(|| {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| runtime().block_on(Distribution::healthy()))
                    .join()
                    .expect("the shared Distribution starts")
            })
        })
    }
}

/// A file for the duration of a test, removed when the test lets go of it.
pub struct ScratchFile(std::path::PathBuf);

impl ScratchFile {
    /// `contents`, in a file of this process's own.
    pub fn holding(contents: &str) -> ScratchFile {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "libid-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("a scratch configuration file");
        ScratchFile(path)
    }

    /// Where it is.
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The client id every fixture deployment enables GitHub with.
pub const CLIENT_ID: &str = "Iv1.0123456789abcdef";

/// The public client credential every fixture deployment publishes
/// for GitHub.
pub const CLIENT_CREDENTIAL: &str = "d3b07384d113edec49eaa6238ad5ff00c1f2e3a4";

impl config::Config {
    /// A configuration that starts, with `args` replacing any default it
    /// names.
    ///
    /// Every flag that reads an environment variable is listed, so the
    /// process environment reaches nothing. `--platforms` is this fixture's
    /// own: the JSON records go to `Config::platforms`, which the binary
    /// fills from the configuration file. The CCDP origin is the shared
    /// Distribution's unless `args` names another.
    pub fn fixture(args: &[&str]) -> config::Config {
        let platforms = format!(
            r#"[{{"id":"github","client_id":"{CLIENT_ID}","versions":[1],"client_credential":"{CLIENT_CREDENTIAL}"}}]"#
        );
        let mut flags: Vec<(&str, &str)> = vec![
            ("--host", "127.0.0.1"),
            ("--port", "8722"),
            ("--allowed-app-origins", "https://app.example"),
            ("--ccdp-origin", Distribution::shared().origin()),
            ("--platforms", &platforms),
        ];
        for pair in args.chunks(2) {
            let [flag, value] = pair else {
                panic!("test flags come in pairs, got {pair:?}")
            };
            match flags.iter_mut().find(|(f, _)| f == flag) {
                Some(slot) => slot.1 = value,
                None => flags.push((flag, value)),
            }
        }
        let platforms = flags
            .iter()
            .position(|(f, _)| *f == "--platforms")
            .map(|i| flags.remove(i).1)
            .expect("the fixture lists --platforms");
        let mut argv = vec!["libid-server-rs"];
        for (flag, value) in &flags {
            argv.push(flag);
            argv.push(value);
        }
        let mut cfg = <config::Config as clap::Parser>::parse_from(argv);
        cfg.platforms =
            serde_json::from_str(platforms).expect("the fixture's platform records");
        cfg
    }
}

impl AppState {
    /// A deployment built from [`config::Config::fixture`], the way the
    /// binary builds one.
    pub async fn fixture(args: &[&str]) -> Arc<AppState> {
        crate::build_state(&config::Config::fixture(args))
            .await
            .expect("a deployment the fixtures can serve")
    }
}
