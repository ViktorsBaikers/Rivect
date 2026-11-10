//! Version-aware docs conformance (AC-037/AC-038, EVAL-005): an old installed
//! version never accepts an incompatible latest API, the no-key direct source
//! answers without paid overage, and stale/304/Accept/auth/redirect answers
//! never create false freshness or carry an Authorization header across an
//! origin. `docs.status` now answers its own owner's real result.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail loudly with the observed payload (standards §14)"
)]

mod support;

use rivect::docs::{
    Authorization, CACHE_MAX_ENTRIES, Cache, CachedDoc, DirectSource, DocsError, Freshness, Quota,
    Redirect, Request, Response, SourceClass, Unknown, classify, plan, redirect, status,
    status_for,
};
use serde_json::json;
use std::path::Path;

/// One versioned docs snapshot tree: a direct source that needs no key.
fn snapshot(tag: &str) -> tempfile::TempDir {
    let directory = tempfile::TempDir::with_prefix(format!("rivect-docs-{tag}-")).expect("tempdir");
    std::fs::create_dir_all(directory.path().join("rivect")).expect("package dir");
    std::fs::write(
        directory.path().join("rivect").join("1.2.0.json"),
        serde_json::to_vec(&json!({
            "package": "rivect",
            "version": "1.2.0",
            "body": "installed-1.2.0 API",
        }))
        .expect("body encodes"),
    )
    .expect("snapshot writes");
    directory
}

fn request<'a>(installed: &'a str, origin: Option<&'a str>) -> Request<'a> {
    Request {
        package: "rivect",
        installed,
        base_url: "https://docs.example.test/api",
        credential_origin: origin,
    }
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        origin: "https://docs.example.test".to_string(),
        body: body.as_bytes().to_vec(),
        etag: None,
        location: None,
    }
}

#[test]
fn installed_version_never_accepts_an_incompatible_latest_api() {
    let directory = snapshot("version-trap");
    let source = DirectSource::new(directory.path());

    let exact = source
        .retrieve("rivect", "1.2.0")
        .expect("the exact snapshot reads");
    let doc = exact.source().expect("the installed version is served");
    assert_eq!(doc.version, "1.2.0");
    assert_eq!(doc.body, "installed-1.2.0 API");
    assert_eq!(doc.freshness, Freshness::Fetched { as_of: 0 });

    // The source holds no latest API, so a missing version is an explicit
    // unknown instead of a silent upgrade.
    let missing = source
        .retrieve("rivect", "2.0.0")
        .expect("a missing version is an answer");
    assert_eq!(
        missing.unknown(),
        Some(&Unknown::VersionUnavailable {
            requested: "2.0.0".to_string()
        })
    );

    // A 200 that declares the latest version for an installed 1.2.0 caller is
    // the old-version/latest trap: never evidence.
    let trap = classify(
        &request("1.2.0", None),
        &response(
            200,
            r#"{"package":"rivect","version":"2.0.0","body":"latest-only API"}"#,
        ),
        None,
        100,
    );
    assert_eq!(
        trap.unknown(),
        Some(&Unknown::VersionMismatch {
            installed: "1.2.0".to_string(),
            offered: "2.0.0".to_string(),
        })
    );

    // A poisoned snapshot claims another package under the requested path.
    std::fs::write(
        directory.path().join("rivect").join("1.2.0.json"),
        serde_json::to_vec(&json!({
            "package": "other",
            "version": "1.2.0",
            "body": "poisoned",
        }))
        .expect("body encodes"),
    )
    .expect("poisoned snapshot writes");
    let poisoned = source
        .retrieve("rivect", "1.2.0")
        .expect("a poisoned snapshot is an answer");
    assert_eq!(
        poisoned.unknown(),
        Some(&Unknown::PoisonedSource {
            package: "other".to_string(),
            version: "1.2.0".to_string(),
        })
    );

    // The poisoned body is never served as evidence, and a request that names
    // no bounded identifier is refused before any path is built.
    assert_eq!(
        source
            .retrieve("../escape", "1.2.0")
            .expect_err("escape")
            .code(),
        rivect::contracts::ErrorCode::InvalidInput
    );
}

#[test]
fn no_key_direct_baseline_answers_without_overage_or_authorization() {
    let directory = snapshot("no-key");
    let source = DirectSource::new(directory.path());
    let no_key = request("1.2.0", None);

    let plan = plan(&no_key).expect("the request is bounded");
    assert_eq!(plan.method, "GET");
    assert_eq!(plan.url, "https://docs.example.test/api/rivect/1.2.0");
    assert!(
        !plan.url.contains("latest"),
        "the plan pins the installed version, never latest: {plan:?}"
    );
    assert_eq!(
        plan.authorization,
        Authorization::None,
        "the no-key baseline carries no credential"
    );

    let answer = source
        .retrieve("rivect", "1.2.0")
        .expect("the direct baseline answers");
    assert!(answer.source().is_some(), "{answer:?}");

    // The status reports the source class and never invents a paid balance.
    let status = status();
    assert_eq!(status.source_classes, vec!["direct_local"]);
    assert_eq!(SourceClass::DirectLocal.as_str(), "direct_local");
    assert_eq!(status.quota, Quota::Unknown);

    // An exhausted SaaS quota leaves the direct baseline usable: the unknown
    // is about the service, not about the local answer.
    let exhausted = classify(&no_key, &response(429, ""), None, 100);
    assert_eq!(exhausted.unknown(), Some(&Unknown::QuotaExhausted));
    assert!(answer.source().is_some(), "the baseline still answers");

    // The same for a refused credential: no retry with another key, and the
    // direct source remains the answer.
    let denied = classify(&no_key, &response(401, ""), None, 100);
    assert_eq!(denied.unknown(), Some(&Unknown::Denied { status: 401 }));
    assert!(source.retrieve("rivect", "1.2.0").is_ok());
}

#[test]
fn stale_and_304_never_create_false_freshness() {
    let no_key = request("1.2.0", None);
    let cached = CachedDoc {
        package: "rivect".to_string(),
        version: "1.2.0".to_string(),
        origin: "https://docs.example.test".to_string(),
        etag: "\"v1\"".to_string(),
        body: "installed-1.2.0 API".to_string(),
        fetched_at: 10,
    };
    let mut cache = Cache::default();
    cache.store(cached.clone());
    assert_eq!(cache.len(), 1);
    assert!(
        cache
            .get("rivect", "1.2.0", "https://docs.example.test")
            .is_some(),
        "the exact scope is cached"
    );
    assert!(
        cache
            .get("rivect", "2.0.0", "https://docs.example.test")
            .is_none(),
        "another version never reads this entry"
    );
    assert!(
        cache
            .get("rivect", "1.2.0", "https://other.example.test")
            .is_none(),
        "another origin never reads this entry"
    );

    // A 304 alone proves nothing: without a scoped entry it is stale.
    let bare = classify(&no_key, &response(304, ""), None, 20);
    assert_eq!(bare.unknown(), Some(&Unknown::Stale));

    // A matching validator and scope revalidates the cached bytes, stamped
    // with the revalidation time rather than pretending a new fetch.
    let mut revalidated = response(304, "");
    revalidated.etag = Some("\"v1\"".to_string());
    let answer = classify(&no_key, &revalidated, Some(&cached), 30);
    let doc = answer.source().expect("the scoped cache revalidates");
    assert_eq!(doc.body, cached.body);
    assert_eq!(doc.freshness, Freshness::Revalidated { as_of: 30 });

    // A different validator is a stale answer, not the cached one.
    let mut changed = revalidated.clone();
    changed.etag = Some("\"v2\"".to_string());
    assert_eq!(
        classify(&no_key, &changed, Some(&cached), 30).unknown(),
        Some(&Unknown::Stale)
    );

    // A 304 from another origin is never folded into the cache scope.
    let mut foreign = revalidated;
    foreign.origin = "https://other.example.test".to_string();
    let answer = classify(&no_key, &foreign, Some(&cached), 30);
    assert_eq!(
        answer.unknown(),
        Some(&Unknown::ForeignOrigin {
            origin: "https://other.example.test".to_string()
        })
    );
}

#[test]
fn accept_and_authorization_are_scoped_to_the_request_origin() {
    // A credential from another origin is withheld, never attached.
    let foreign = request("1.2.0", Some("https://other.example.test"));
    assert_eq!(
        plan(&foreign).expect("bounded").authorization,
        Authorization::Withheld
    );

    // The same origin keeps it scoped, and the plan names the installed
    // version in its URL.
    let scoped = request("1.2.0", Some("https://docs.example.test"));
    let plan = plan(&scoped).expect("bounded");
    assert_eq!(plan.authorization, Authorization::Scoped);
    assert_eq!(plan.accept, "application/json");

    // A same-origin redirect stays scoped; a cross-origin one is refused with
    // the header withheld, so a redirect can never leak the Authorization.
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "/api/rivect/1.2.0",
            Some("https://docs.example.test")
        ),
        Redirect::Follow {
            url: "/api/rivect/1.2.0".to_string(),
            authorization: Authorization::Scoped,
        }
    );
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "https://evil.example.test/steal",
            Some("https://docs.example.test")
        ),
        Redirect::Refused {
            origin: "https://evil.example.test".to_string(),
            authorization: Authorization::Withheld,
        }
    );

    // A cross-origin 30x response is an explicit unknown, never an answer.
    let mut moved = response(302, "");
    moved.location = Some("https://evil.example.test/steal".to_string());
    let answer = classify(&request("1.2.0", None), &moved, None, 100);
    assert_eq!(
        answer.unknown(),
        Some(&Unknown::CrossOriginRedirect {
            origin: "https://evil.example.test".to_string()
        })
    );

    // A same-origin redirect is re-planned rather than served as content.
    let mut inside = response(307, "");
    inside.location = Some("https://docs.example.test/api/rivect/1.2.0/full".to_string());
    let answer = classify(&request("1.2.0", None), &inside, None, 100);
    assert!(
        matches!(answer.unknown(), Some(&Unknown::Redirect { .. })),
        "{answer:?}"
    );
}

#[test]
fn malformed_and_oversized_documents_are_unknown_never_evidence() {
    let no_key = request("1.2.0", None);
    // A 200 whose body is not the declared header is malformed.
    let answer = classify(&no_key, &response(200, "{not json"), None, 100);
    assert_eq!(answer.unknown(), Some(&Unknown::Malformed));

    // A 200 whose declared package is another one is poisoned.
    let answer = classify(
        &no_key,
        &response(
            200,
            r#"{"package":"other","version":"1.2.0","body":"impostor"}"#,
        ),
        None,
        100,
    );
    assert!(
        matches!(answer.unknown(), Some(&Unknown::PoisonedSource { .. })),
        "{answer:?}"
    );

    // A 5xx is an upstream unknown, not a stale body.
    let answer = classify(&no_key, &response(503, ""), None, 100);
    assert_eq!(answer.unknown(), Some(&Unknown::Upstream { status: 503 }));

    // A body past the accepted bound is refused at the classifier.
    let huge = "x".repeat(rivect::docs::DOC_BODY_MAX_BYTES + 1);
    let mut oversized = response(200, "");
    oversized.body = huge.into_bytes();
    let answer = classify(&no_key, &oversized, None, 100);
    assert!(
        matches!(answer.unknown(), Some(&Unknown::TooLarge { .. })),
        "{answer:?}"
    );

    // The director source refuses an unreadable root with a typed failure,
    // never an empty answer.
    let missing_root = Path::new("/nonexistent/rivect-docs-root");
    let source = DirectSource::new(missing_root);
    let answer = source
        .retrieve("rivect", "1.2.0")
        .expect("a missing version is an answer, not a failure");
    assert!(matches!(
        answer.unknown(),
        Some(&Unknown::VersionUnavailable { .. })
    ));
    assert!(matches!(
        source.retrieve("../escape", "1.2.0"),
        Err(DocsError::InvalidRequest { .. })
    ));
}

#[test]
fn docs_status_is_available_and_reports_a_real_result() {
    // The catalog row is served, not merely advertised.
    let page = rivect::tools::describe();
    let row = page
        .items
        .iter()
        .find(|item| item.canonical_id == "docs.status")
        .expect("docs.status is a catalog row");
    assert!(row.available, "{row:?}");
    assert!(row.unavailability_reason.is_none(), "{row:?}");
    assert_eq!(
        rivect::tools::local_command_kind("docs.status"),
        rivect::tools::LocalKind::DocsStatus
    );

    // The status is the owner's own projection: the direct source, version
    // policy, bounded cache and an honest unknown quota.
    let status = status();
    assert_eq!(status.schema_version, 1);
    assert_eq!(status.kind, "docs.status");
    assert_eq!(status.owner, "src/docs.rs");
    assert!(status.version_aware);
    assert_eq!(status.source_classes, vec!["direct_local"]);
    assert_eq!(status.cache.max_entries, CACHE_MAX_ENTRIES);
    assert_eq!(status.cache.cached_entries, 0);
    assert_eq!(status.quota, Quota::Unknown);

    // A caller-held cache is reflected, not hidden.
    let mut cache = Cache::default();
    cache.store(CachedDoc {
        package: "rivect".to_string(),
        version: "1.2.0".to_string(),
        origin: "https://docs.example.test".to_string(),
        etag: "\"v1\"".to_string(),
        body: "body".to_string(),
        fetched_at: 1,
    });
    assert_eq!(status_for(&cache).cache.cached_entries, 1);

    // The dispatcher answers the same result through the public surface, and
    // the command is a pure read: no external refresh is triggered.
    let mut world = support::open_world("docs-status", None);
    let session = world.open_session("docs-status");
    let response = world.dispatch(&support::command_execute(
        &session,
        "docs.status",
        json!({}),
    ));
    assert!(response.get("error").is_none(), "{response}");
    let result = &response["result"];
    assert_eq!(result["kind"], "docs.status", "{response}");
    assert_eq!(result["owner"], "src/docs.rs", "{response}");
    assert_eq!(
        result["source_classes"],
        json!(["direct_local"]),
        "{response}"
    );
    assert_eq!(result["version_aware"], true, "{response}");
    assert_eq!(result["quota"], "unknown", "{response}");
    assert_eq!(
        result["cache"]["max_entries"], CACHE_MAX_ENTRIES,
        "{response}"
    );

    // No account was touched: the process still holds no credential and the
    // row answered from its own owner.
    assert_eq!(status.quota, Quota::Unknown);
}
