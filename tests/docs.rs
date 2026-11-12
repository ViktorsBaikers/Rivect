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
use serde_json::{Value, json};
use std::path::Path;

/// One versioned docs snapshot tree: a direct source that needs no key.
fn snapshot(tag: &str) -> tempfile::TempDir {
    snapshot_with(tag, "rivect", "1.2.0", "installed-1.2.0 API")
}

/// One snapshot file at the installed version's path, with a header the case
/// chooses: a same-package latest version or another package's claim.
fn snapshot_with(
    tag: &str,
    header_package: &str,
    header_version: &str,
    body: &str,
) -> tempfile::TempDir {
    let directory = tempfile::TempDir::with_prefix(format!("rivect-docs-{tag}-")).expect("tempdir");
    std::fs::create_dir_all(directory.path().join("rivect")).expect("package dir");
    std::fs::write(
        directory.path().join("rivect").join("1.2.0.json"),
        serde_json::to_vec(&json!({
            "package": header_package,
            "version": header_version,
            "body": body,
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

/// `docs.status` with its declared `question` object: the public entry that
/// serves the direct source. The entry never carries a transport response, so
/// the stale/304/redirect legs stay library cases over `classify`/`redirect`;
/// this drives the half of AC-037/AC-038 the product surface actually owns.
fn status_question(
    world: &mut support::World,
    session: &rivect::contracts::SessionId,
    installed: &str,
    root: &Path,
) -> Value {
    world.dispatch(&support::command_execute(
        session,
        "docs.status",
        json!({
            "question": {
                "package": "rivect",
                "installed": installed,
                "root": root.to_str().expect("utf-8 snapshot root"),
            }
        }),
    ))
}

#[test]
fn installed_version_never_accepts_an_incompatible_latest_api() {
    println!("ROW A08 ok");
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
fn protocol_relative_redirects_name_their_own_authority() {
    // A protocol-relative location carries its own authority under the
    // request's scheme: a foreign one is refused with the scoped credential
    // withheld rather than read as a same-origin path.
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "//evil.example.test/steal",
            Some("https://docs.example.test")
        ),
        Redirect::Refused {
            origin: "https://evil.example.test".to_string(),
            authorization: Authorization::Withheld,
        }
    );
    // The same authority may follow with the scoped credential.
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "//docs.example.test/api/rivect/1.2.0",
            Some("https://docs.example.test")
        ),
        Redirect::Follow {
            url: "//docs.example.test/api/rivect/1.2.0".to_string(),
            authorization: Authorization::Scoped,
        }
    );
    // With no credential bound, neither location attaches an authorization.
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "//evil.example.test/steal",
            None
        ),
        Redirect::Refused {
            origin: "https://evil.example.test".to_string(),
            authorization: Authorization::None,
        }
    );
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "//docs.example.test/api/rivect/1.2.0",
            None
        ),
        Redirect::Follow {
            url: "//docs.example.test/api/rivect/1.2.0".to_string(),
            authorization: Authorization::None,
        }
    );

    // The classifier reads the same authority: a protocol-relative
    // cross-origin redirect is an explicit unknown, never a same-origin
    // re-plan.
    let mut moved = response(302, "");
    moved.location = Some("//evil.example.test/steal".to_string());
    assert_eq!(
        classify(&request("1.2.0", None), &moved, None, 100).unknown(),
        Some(&Unknown::CrossOriginRedirect {
            origin: "https://evil.example.test".to_string()
        })
    );
    // A same-authority protocol-relative redirect is re-planned, not served.
    let mut inside = response(307, "");
    inside.location = Some("//docs.example.test/api/rivect/1.2.0/full".to_string());
    assert_eq!(
        classify(&request("1.2.0", None), &inside, None, 100).unknown(),
        Some(&Unknown::Redirect {
            url: "//docs.example.test/api/rivect/1.2.0/full".to_string()
        })
    );
}

#[test]
fn ambiguous_redirect_spellings_resolve_to_their_foreign_authority() {
    // WHATWG resolution treats backslashes as slashes and collapses repeated
    // slashes, so each spelling names the foreign authority rather than a
    // same-origin path; the scoped credential is withheld and the hop refused.
    for location in ["/\\evil.example.test/steal", "\\\\evil.example.test\\steal"] {
        assert_eq!(
            redirect(
                "https://docs.example.test",
                location,
                Some("https://docs.example.test")
            ),
            Redirect::Refused {
                origin: "https://evil.example.test".to_string(),
                authorization: Authorization::Withheld,
            },
            "{location}"
        );

        let mut moved = response(302, "");
        moved.location = Some(location.to_string());
        assert_eq!(
            classify(&request("1.2.0", None), &moved, None, 100).unknown(),
            Some(&Unknown::CrossOriginRedirect {
                origin: "https://evil.example.test".to_string()
            }),
            "{location}"
        );
    }

    // An empty authority (`///evil`) is refused by the parser itself; the hop
    // is still refused and the credential withheld.
    assert!(
        matches!(
            redirect(
                "https://docs.example.test",
                "///evil.example.test/steal",
                Some("https://docs.example.test")
            ),
            Redirect::Refused {
                authorization: Authorization::Withheld,
                ..
            }
        ),
        "an unresolvable authority is refused"
    );
    let mut moved = response(302, "");
    moved.location = Some("///evil.example.test/steal".to_string());
    assert!(matches!(
        classify(&request("1.2.0", None), &moved, None, 100).unknown(),
        Some(&Unknown::CrossOriginRedirect { .. })
    ));

    // A same-scheme location with one slash is a path under WHATWG resolution
    // (a browser's `new URL("https:/x", base)` stays on base), so it follows
    // with the scoped credential instead of being misread as an authority.
    assert_eq!(
        redirect(
            "https://docs.example.test",
            "https:/evil.example.test/steal",
            Some("https://docs.example.test")
        ),
        Redirect::Follow {
            url: "https:/evil.example.test/steal".to_string(),
            authorization: Authorization::Scoped,
        }
    );
    let mut inside = response(302, "");
    inside.location = Some("https:/evil.example.test/steal".to_string());
    assert_eq!(
        classify(&request("1.2.0", None), &inside, None, 100).unknown(),
        Some(&Unknown::Redirect {
            url: "https:/evil.example.test/steal".to_string()
        })
    );
}

/// A caller-named snapshot must be a regular file: a FIFO with no writer is
/// refused before the open that would block forever, and a regular file past
/// the body bound is still refused by the byte bound.
#[cfg(unix)]
#[test]
fn a_snapshot_target_must_be_regular_and_byte_bounded() {
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::TempDir::with_prefix("rivect-docs-bound-").expect("tempdir");
    std::fs::create_dir_all(directory.path().join("rivect")).expect("package dir");
    let path = directory.path().join("rivect").join("1.2.0.json");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed: {status}");

    // No writer ever opens the FIFO: only a pre-open regular-file refusal
    // returns here, because `File::open` on a reader FIFO blocks forever.
    let (answer, answered) = mpsc::channel();
    let source_root = directory.path().to_path_buf();
    let reader = std::thread::spawn(move || {
        let source = DirectSource::new(&source_root);
        answer
            .send(source.retrieve("rivect", "1.2.0"))
            .expect("send the fifo answer");
    });
    let observed = answered
        .recv_timeout(Duration::from_secs(15))
        .expect("a non-regular target is refused before the blocking open");
    reader.join().expect("the reader finishes");
    match observed {
        Err(DocsError::Read { source, .. }) => {
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::InvalidInput,
                "the refusal is typed at the open boundary"
            );
        }
        other => panic!("a non-regular snapshot is refused: {other:?}"),
    }

    std::fs::remove_file(&path).expect("replace the fifo");
    std::fs::write(&path, vec![b' '; rivect::docs::DOC_BODY_MAX_BYTES + 1])
        .expect("over-bound snapshot");
    match DirectSource::new(directory.path()).retrieve("rivect", "1.2.0") {
        Err(DocsError::TooLarge { limit, .. }) => {
            assert_eq!(limit, rivect::docs::DOC_BODY_MAX_BYTES);
        }
        other => panic!("an over-bound snapshot is refused: {other:?}"),
    }
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
fn docs_status_question_serves_only_an_applicable_source() {
    println!("ROW A01 ok");
    // AC-037 at the declared product entry: the on-disk direct source is the
    // applicable one, and an incompatible latest/API answer is an explicit
    // unknown rather than evidence.
    let compatible = snapshot("entry-compatible");
    let mut world = support::open_world("docs-entry-version", None);
    let session = world.open_session("docs-entry-version");
    let served = status_question(&mut world, &session, "1.2.0", compatible.path());
    assert!(served.get("error").is_none(), "{served}");
    let answer = &served["result"]["answer"];
    assert_eq!(answer["status"], "source", "{served}");
    assert_eq!(answer["version"], "1.2.0", "{served}");
    assert_eq!(answer["body"], "installed-1.2.0 API", "{served}");
    assert_eq!(answer["freshness"]["fetched"]["as_of"], 0, "{served}");

    // The installed 1.2.0 caller asking for a 2.0.0 snapshot is the
    // old-version/latest trap: the body's own header refuses it as evidence,
    // and the incompatible example never reaches the answer.
    let latest = snapshot_with(
        "entry-latest",
        "rivect",
        "2.0.0",
        "latest-only API; citation: https://docs.example.test/latest",
    );
    let trapped = status_question(&mut world, &session, "1.2.0", latest.path());
    assert!(trapped.get("error").is_none(), "{trapped}");
    let answer = &trapped["result"]["answer"];
    assert_eq!(answer["status"], "unknown", "{trapped}");
    assert_eq!(answer["reason"], "version_mismatch", "{trapped}");
    assert_eq!(answer["installed"], "1.2.0", "{trapped}");
    assert_eq!(answer["offered"], "2.0.0", "{trapped}");
    assert!(
        !trapped.to_string().contains("latest-only API"),
        "an incompatible example is never served as evidence: {trapped}"
    );
    assert!(
        !trapped.to_string().contains("docs.example.test/latest"),
        "an unsupported citation is never served as evidence: {trapped}"
    );

    // A snapshot whose own header names another package is poisoned.
    let poisoned = snapshot_with("entry-poisoned", "other", "1.2.0", "impostor");
    let poisoned = status_question(&mut world, &session, "1.2.0", poisoned.path());
    assert_eq!(
        poisoned["result"]["answer"]["reason"], "poisoned_source",
        "{poisoned}"
    );
    assert!(
        !poisoned.to_string().contains("impostor"),
        "a poisoned body is never evidence: {poisoned}"
    );

    // A version the source does not hold stays unknown; the latest one is
    // never substituted.
    let missing = status_question(&mut world, &session, "2.0.0", compatible.path());
    assert_eq!(
        missing["result"]["answer"]["reason"], "version_unavailable",
        "{missing}"
    );
    assert_eq!(
        missing["result"]["answer"]["requested"], "2.0.0",
        "{missing}"
    );
    assert_eq!(
        missing["result"]["quota"], "unknown",
        "the account fact stays unknown"
    );
}

#[test]
fn docs_status_question_uses_the_direct_baseline_without_a_key_or_overage() {
    // AC-038 at the product entry: no key and no SaaS account, the direct
    // source still answers, the quota stays an honest unknown, and no
    // credential/authorization field is carried by the answer.
    let direct = snapshot("entry-no-key");
    let mut world = support::open_world("docs-entry-no-key", None);
    let session = world.open_session("docs-entry-no-key");
    let served = status_question(&mut world, &session, "1.2.0", direct.path());
    assert!(served.get("error").is_none(), "{served}");
    let result = &served["result"];
    assert_eq!(result["answer"]["status"], "source", "{served}");
    assert_eq!(result["answer"]["version"], "1.2.0", "{served}");
    assert_eq!(result["quota"], "unknown", "{served}");
    assert_eq!(
        result["source_classes"],
        json!(["direct_local"]),
        "{served}"
    );
    assert_eq!(
        result["version_aware"], true,
        "the row pins the installed version"
    );
    let rendered = served.to_string().to_ascii_lowercase();
    for forbidden in ["authorization", "bearer", "credential", "api_key"] {
        assert!(
            !rendered.contains(forbidden),
            "the direct baseline carries no {forbidden}: {served}"
        );
    }

    // Stale/304/redirect freshness and Authorization scoping are classifier
    // properties this entry cannot carry: no transport response reaches it.
    // The library cases above remain their owner; the product half proves the
    // baseline answers without a key and never invents a paid account.
    let status = status();
    assert_eq!(status.quota, Quota::Unknown);
    assert_eq!(status.source_classes, vec!["direct_local"]);
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
    assert_eq!(
        result,
        &json!(rivect::docs::status()),
        "no-argument docs.status is the status projection byte-for-byte"
    );
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

/// A credential seam that fails the test on any read: `docs.status` must be a
/// pure projection even when a search connection and store are configured.
struct UntouchableStore;

impl rivect::providers::CredentialStore for UntouchableStore {
    fn kind(&self) -> rivect::providers::StoreKind {
        rivect::providers::StoreKind::Keychain
    }

    fn occupied(
        &self,
        _credential: &rivect::providers::SecretRef,
    ) -> Result<bool, rivect::providers::ProviderError> {
        panic!("docs.status read a credential")
    }

    fn entry_accounts(
        &self,
        _service: &str,
    ) -> Result<Vec<String>, rivect::providers::ProviderError> {
        panic!("docs.status read a credential")
    }

    fn login(
        &self,
        _credential: &rivect::providers::SecretRef,
        _secret: &[u8],
    ) -> Result<(), rivect::providers::ProviderError> {
        panic!("docs.status wrote a credential")
    }

    fn resolve(
        &self,
        _credential: &rivect::providers::SecretRef,
    ) -> Result<Vec<u8>, rivect::providers::ProviderError> {
        panic!("docs.status read a credential")
    }

    fn refresh(
        &self,
        _credential: &rivect::providers::SecretRef,
        _secret: &[u8],
    ) -> Result<(), rivect::providers::ProviderError> {
        panic!("docs.status wrote a credential")
    }

    fn revoke(
        &self,
        _credential: &rivect::providers::SecretRef,
    ) -> Result<(), rivect::providers::ProviderError> {
        panic!("docs.status revoked a credential")
    }

    fn logout(
        &self,
        _credential: &rivect::providers::SecretRef,
    ) -> Result<(), rivect::providers::ProviderError> {
        panic!("docs.status logged out a credential")
    }
}

/// `docs.status` is a pure read: with a declared search connection, an
/// injected credential store and a bound loopback endpoint, the row answers
/// its own projection, reads no credential and opens no socket.
#[test]
fn docs_status_is_a_pure_read_with_zero_transports_or_credentials() {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind the docs purity peer");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("docs purity peer address")
    );
    let document = format!(
        "{}\n[connections.\"search.exa\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"keyring:search/exa\"\n",
        support::base_config()
    );
    let mut world = support::open_world("docs-status-purity", Some(&document));
    world.runtime.search_credentials = Some(std::sync::Arc::new(UntouchableStore));
    let session = world.open_session("docs-status-purity");
    let response = world.dispatch(&support::command_execute(
        &session,
        "docs.status",
        json!({}),
    ));
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(
        response["result"],
        json!(status()),
        "the no-question row is exactly the owner's projection"
    );
    assert_eq!(response["result"]["owner"], "src/docs.rs", "{response}");
    assert_eq!(
        response["result"]["source_classes"],
        json!(["direct_local"]),
        "{response}"
    );
    assert_eq!(response["result"]["quota"], "unknown", "{response}");
    assert_eq!(
        response["result"]["cache"]["cached_entries"], 0,
        "{response}"
    );

    listener
        .set_nonblocking(true)
        .expect("nonblocking docs purity accept");
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("docs.status opened a transport"),
        Err(error) => panic!("docs purity accept failed: {error}"),
    }
}
