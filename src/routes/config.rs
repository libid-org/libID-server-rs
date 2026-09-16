//! The public ceremony configuration: `{ ccdpOrigin, platforms }`, one record
//! built at startup and served to every admitted origin, and to a same-origin
//! read. It carries no secret, no admitted origin, no asset URL and no notary
//! setting. A browser that must preflight its `GET` is answered here too, by
//! the same admission rule.

use std::sync::Arc;

use axum::{
    extract::{
        RawQuery,
        State,
    },
    http::{
        header,
        HeaderMap,
        HeaderName,
        HeaderValue,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
    Json,
};
use serde_json::json;

use super::ON_EVERY_RESPONSE;
use crate::state::AppState;

/// What `Vary` names, on every response this route writes: `Origin` and
/// `Sec-Fetch-Site` decide the body, on refusals too.
const VARY_ON: &str = "origin, sec-fetch-site";

/// The fetch metadata header saying where a browser request came from,
/// relative to its target.
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// What `Vary` names on a preflight: the origin admitted and the headers the
/// answer grants.
const PREFLIGHT_VARY_ON: &str = "origin, access-control-request-headers";

/// How long a browser may reuse one preflight answer. The admission set and
/// the method granted are fixed at startup.
const PREFLIGHT_MAX_AGE: &str = "600";

/// How a request is admitted to read the configuration.
enum Admission {
    /// One `Origin`, matching an admitted origin exactly; echoed as the
    /// allow-origin.
    Listed(HeaderValue),
    /// No `Origin`: a same-origin browser `GET`, which carries none, on
    /// `Sec-Fetch-Site: same-origin`. It needs no CORS header.
    SameOrigin,
}

/// How this request may read the configuration, or `None`.
///
/// One `Origin` must match an admitted origin exactly: `null`, a malformed
/// value, an unlisted one and two headers are refused whatever else the
/// request carries. With no `Origin`, exactly one `Sec-Fetch-Site:
/// same-origin` admits. `Referer`, the request host and absent fetch
/// metadata admit nothing.
fn admission(state: &AppState, headers: &HeaderMap) -> Option<Admission> {
    match crate::routes::Origins::of(headers) {
        crate::routes::Origins::One(origin) => {
            let value = origin.to_str().ok()?;
            state
                .allowed_origins
                .iter()
                .any(|a| a.as_str() == value)
                .then(|| Admission::Listed(origin.clone()))
        }
        crate::routes::Origins::Several => None,
        crate::routes::Origins::Absent => {
            let mut sites = headers.get_all(SEC_FETCH_SITE).iter();
            match (sites.next(), sites.next()) {
                (Some(site), None) if site == "same-origin" => {
                    Some(Admission::SameOrigin)
                }
                _ => None,
            }
        }
    }
}

/// `OPTIONS /api/v1/ceremony/config`: the preflight a browser sends before a
/// `GET` carrying a header a simple request may not.
///
/// It admits what the `GET` admits: exactly one `Origin`, in the effective
/// set. A preflight carries one by definition, so the same-origin case is not
/// one and is refused like any other. The answer grants `GET`, the headers the
/// request asked for, and no credentials.
pub(crate) async fn preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let Some(Admission::Listed(origin)) = admission(&state, &headers) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "this configuration is readable only from an admitted origin",
        );
    };

    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(PREFLIGHT_VARY_ON));
    out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    out.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET"),
    );
    out.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(PREFLIGHT_MAX_AGE),
    );
    // The record is public and read without credentials, so the headers a
    // caller wants to send are granted as asked rather than from a list this
    // service would have to keep.
    if let Some(asked) = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, asked.clone());
    }
    for (name, value) in ON_EVERY_RESPONSE {
        out.insert(name, value);
    }

    (StatusCode::NO_CONTENT, out).into_response()
}

/// `GET /api/v1/ceremony/config`.
pub(crate) async fn config(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    // Admission is decided before anything else is looked at.
    let Some(admission) = admission(&state, &headers) else {
        return refuse(
            StatusCode::FORBIDDEN,
            "this configuration is readable only from an admitted origin",
        );
    };

    if query.is_some_and(|q| !q.is_empty()) {
        return refuse(StatusCode::BAD_REQUEST, "this route takes no query");
    }

    // `insert`, not append: the `Bytes` body would otherwise add its own
    // content type.
    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (name, value) in ON_EVERY_RESPONSE {
        out.insert(name, value);
    }
    // The exact origin that asked, never `*`; no credentials. A same-origin
    // read gets no allow-origin.
    if let Admission::Listed(origin) = admission {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }

    (StatusCode::OK, out, state.ceremony_config.clone()).into_response()
}

/// A refusal carries no configuration and no allow-origin header, so a caller
/// that is not admitted cannot read the record out of an error, and a
/// preflight it answers grants nothing. A browser reads neither body.
fn refuse(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::VARY, VARY_ON)],
        ON_EVERY_RESPONSE,
        Json(json!({ "message": message })),
    )
        .into_response()
}
