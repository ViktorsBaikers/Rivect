//! Scoped credential-profile proof (SRC-010, DEC-002/009/013/014,
//! INV-001/006/009): the `SecretRef` + `CredentialStore` seam is the only
//! path from a native secret store to an adapter. Secret bytes never leave
//! the store boundary — config, diagnostics, Debug/Display, the request
//! manifest and the test journal see scoped refs only. Lifecycle roundtrips
//! hold for every admitted auth class, a neighbor profile stays
//! byte-identical through another profile's lifecycle, unavailable or
//! ambiguous stores surface as named typed errors with no plaintext
//! fallback, and per-profile refresh coalesces to one in-flight op. The
//! real `rivect-test` Keychain leg creates and deletes its own entries
//! under a bounded journal that survives teardown.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/print/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::config::{Config, ConfigIssue, ConfigValue, EffortAssign, ModelAssign};
use rivect::model::RequestManifest;
use rivect::providers::{
    CredentialStore, FlightedStore, KeyringBackend, ProviderError, SecretRef, SecretRefError,
    StoreKind, native_store, resolve_credential,
};
use serde_json::{Value, json};
use std::any::Any;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, mpsc};
use std::time::Duration;
use support::SECRET_CANARY;

/// The only namespace the proof may write to (DEC-002): a service prefix
/// that can never collide with production `rivect` entries or foreign
/// keychain data.
const TEST_NAMESPACE: &str = "rivect-test";
/// Bounded retained journal: one JSON row `{op, boundary_id, namespace,
/// result}` per store op, fingerprints only, under `target/` so teardown
/// never deletes it.
const JOURNAL_PATH: &str = "target/rivect-auth/journal.jsonl";
const JOURNAL_CAP: usize = 512;
/// A locked keychain answers or the probe reports BLOCKED — a modal prompt
/// parks the probe thread, never the suite's bounded wait on it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// The admitted auth classes across the eight connection IDs (spec table):
/// env/credential-chain (openai, google, aimlapi), configured-origin
/// (custom-chat-completions), api-key (abliteration, aiand) and
/// custom/region-aware (alibaba-coding-plan, alibaba-token-plan).
const AUTH_CLASSES: &[&str] = &[
    "env-credential-chain",
    "configured-origin",
    "api-key",
    "custom-region-aware",
];

/// The platform's native store class — the same mapping `keyring:`
/// applies inside the seam under test (macOS → Keychain, Linux → Secret
/// Service, other platforms resolve Keychain and simply never admit a
/// store).
#[cfg(target_os = "linux")]
const NATIVE_KIND: StoreKind = StoreKind::SecretService;
#[cfg(not(target_os = "linux"))]
const NATIVE_KIND: StoreKind = StoreKind::Keychain;

fn scoped_ref(scope_tail: &str) -> SecretRef {
    SecretRef::parse(&format!("keyring:{TEST_NAMESPACE}/{scope_tail}")).expect("test ref is scoped")
}

/// A ref pinned to the Keychain class regardless of host platform: the
/// scripted-backend and counting-store legs report `StoreKind::Keychain`,
/// so `keyring:` — which resolves to the native class — would name a
/// foreign class on Linux.
fn keychain_ref(scope_tail: &str) -> SecretRef {
    SecretRef::parse(&format!("keychain:{TEST_NAMESPACE}/{scope_tail}"))
        .expect("test ref is scoped")
}

// ----- journal ---------------------------------------------------------

/// The DEC-002 bounded journal: append-only rows of exactly
/// `{op, boundary_id, namespace, result}` — boundary ids are scoped refs
/// and results are verdicts or secret fingerprints, never secret bytes.
struct AuthJournal {
    file: std::fs::File,
    lines: usize,
}

/// Serializes row appends: parallel cases share the journal file, and a
/// `writeln!` on a `File` emits one `write` per format piece — without a
/// lock the rows byte-interleave. The lock plus a single `write_all`
/// keeps every row intact.
static JOURNAL_LOCK: Mutex<()> = Mutex::new(());

/// Serializes cases that touch a real native store: an enumerate-all
/// `search` can transiently miss a just-committed entry while a parallel
/// case mutates the same keychain, so real-store legs run one case at a
/// time. Cases over scripted or in-memory stores never take it.
static STORE_CASES: Mutex<()> = Mutex::new(());

impl AuthJournal {
    fn open(case: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(JOURNAL_PATH);
        std::fs::create_dir_all(path.parent().expect("journal dir")).expect("journal dir");
        // The journal is per-run evidence: the first open of a process
        // truncates it, so the file stays bounded across runs (the
        // per-instance cap only bounds one case). `call_once` serializes
        // the first openers — every row is written after its case's open
        // returned, hence after the truncate.
        static TRUNCATE: Once = Once::new();
        TRUNCATE.call_once(|| {
            std::fs::write(&path, "").expect("journal truncate");
        });
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("journal opens");
        let mut journal = Self { file, lines: 0 };
        journal.record("case", case, TEST_NAMESPACE, "begin");
        journal
    }

    fn record(&mut self, op: &str, boundary_id: &str, namespace: &str, result: &str) {
        assert!(
            self.lines < JOURNAL_CAP,
            "journal bound exceeded — unbounded audit growth"
        );
        let row = json!({
            "op": op,
            "boundary_id": boundary_id,
            "namespace": namespace,
            "result": result,
        });
        let _guard = JOURNAL_LOCK.lock().expect("journal lock is not poisoned");
        self.file
            .write_all(format!("{row}\n").as_bytes())
            .expect("journal write");
        self.lines += 1;
    }
}

fn journal_text() -> String {
    let _guard = JOURNAL_LOCK.lock().expect("journal lock is not poisoned");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(JOURNAL_PATH);
    std::fs::read_to_string(path).expect("journal readable")
}

/// The parsed journal — case-scoped assertions filter on `boundary_id`
/// instead of substring-matching the whole file (a global `contains`
/// would pass on another case's row).
fn journal_rows() -> Vec<Value> {
    journal_text()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("journal row parses"))
        .collect()
}

/// The `ProviderError` variant name — the only error detail a journal row
/// or stderr line may carry. `Display`/`Debug` text can embed platform
/// passthrough material (`map_error` pins `reason` verbatim), so raw
/// error text never reaches either surface.
fn error_variant(err: &ProviderError) -> &'static str {
    match err {
        ProviderError::UnknownConnection { .. } => "UnknownConnection",
        ProviderError::LiveGrantRequired { .. } => "LiveGrantRequired",
        ProviderError::StoreUnavailable { .. } => "StoreUnavailable",
        ProviderError::StoreAmbiguous { .. } => "StoreAmbiguous",
        ProviderError::CredentialUnresolved { .. } => "CredentialUnresolved",
        ProviderError::CredentialProfileMismatch { .. } => "CredentialProfileMismatch",
        ProviderError::CredentialOutsideNamespace { .. } => "CredentialOutsideNamespace",
        ProviderError::CredentialOccupied { .. } => "CredentialOccupied",
        ProviderError::CredentialAbsent { .. } => "CredentialAbsent",
        ProviderError::CredentialMalformed { .. } => "CredentialMalformed",
        ProviderError::CredentialBaseMismatch { .. } => "CredentialBaseMismatch",
        ProviderError::DialectMismatch { .. } => "DialectMismatch",
        ProviderError::DialectUnserved { .. } => "DialectUnserved",
        ProviderError::UnpinnedModel { .. } => "UnpinnedModel",
        ProviderError::RegionMismatch { .. } => "RegionMismatch",
        ProviderError::Transport { .. } => "Transport",
        ProviderError::ProviderFailed { .. } => "ProviderFailed",
        ProviderError::UnknownTerminal { .. } => "UnknownTerminal",
        ProviderError::StreamViolation { .. } => "StreamViolation",
        ProviderError::IncompatibleOutput { .. } => "IncompatibleOutput",
        ProviderError::ReasoningProvenance { .. } => "ReasoningProvenance",
    }
}

/// `"ok"` or the error's variant name — the stderr-safe rendering of a
/// `Result<_, ProviderError>` for assert and panic messages.
fn outcome_variant<T>(result: &Result<T, ProviderError>) -> &'static str {
    result.as_ref().err().map_or("ok", error_variant)
}

/// Journal verdict for a store error: the variant name plus a sha256
/// fingerprint of the rendered text — the row pins WHICH error fired
/// without retaining text that can carry platform-embedded material.
fn error_verdict(err: &ProviderError) -> String {
    format!(
        "{} sha256:{}",
        error_variant(err),
        support::sha256_hex(err.to_string().as_bytes())
    )
}

/// The consumptive-gate boundary map (test-plan "Boundary map +
/// collision proof"; one-shot-actions §5): every journaled op names
/// exactly one seam identity. Emit sites sharing a planned seam keep
/// disjoint boundary-id spaces — precheck verdicts key on scope refs,
/// the census on account names, probes on case names — and `refresh` /
/// `logout` get their own identities because they emit on the same
/// boundary id as `login` / `revoke` inside one lifecycle leg. Ops that
/// never reach a real store — scripted-backend legs and case
/// bookkeeping — land on `AUTH-SCRIPTED`, which evidences no boundary
/// and is exempt from fingerprint injectivity.
fn seam_of(op: &str) -> Option<&'static str> {
    Some(match op {
        "precheck" | "census" | "reap" | "probe" => "AUTH-KC-PRECHECK",
        "create" | "login" => "AUTH-KC-CREATE",
        "resolve" => "AUTH-KC-READ",
        "delete" | "revoke" | "teardown" => "AUTH-KC-DELETE",
        "refresh" => "AUTH-KC-REFRESH",
        "logout" => "AUTH-KC-LOGOUT",
        "unavailable" => "AUTH-STORE-UNAVAILABLE",
        "ambiguous" => "AUTH-STORE-AMBIGUOUS",
        "case" | "status" | "lifecycle" | "guard" | "fingerprint" => "AUTH-SCRIPTED",
        _ => return None,
    })
}

/// Asserts a journal row set honors the boundary map: every row's op is
/// in the closed vocabulary, and no two distinct ops claim one
/// `(seam, boundary_id)` evidence identity — a retained fingerprint
/// identifies exactly one emit site, so a row can never satisfy another
/// op's seam assertion. Distinct seams may share a boundary freely: a
/// lifecycle leg records precheck, resolve and revoke on one scope.
fn check_boundary_map(rows: &[Value]) -> Result<(), String> {
    let mut claimed: HashMap<(&str, &str), &str> = HashMap::new();
    for row in rows {
        let op = row["op"]
            .as_str()
            .ok_or_else(|| "journal row has no string op".to_string())?;
        let boundary_id = row["boundary_id"]
            .as_str()
            .ok_or_else(|| format!("journal row for op {op} has no string boundary_id"))?;
        let Some(seam) = seam_of(op) else {
            return Err(format!("journal op {op} is outside the boundary map"));
        };
        if seam == "AUTH-SCRIPTED" {
            continue;
        }
        if let Some(other) = claimed.insert((seam, boundary_id), op)
            && other != op
        {
            return Err(format!(
                "ops {other} and {op} both claim {seam} evidence at {boundary_id}"
            ));
        }
    }
    Ok(())
}

// ----- native-store probe ----------------------------------------------

enum Probe {
    Available(FlightedStore),
    Unavailable(ProviderError),
    /// The probe exceeded its wait bound — treated as an honest BLOCKED
    /// status, never a hung suite.
    Blocked,
}

/// Opens the `rivect-test` namespace on the platform store and probes one
/// scoped read inside a bounded wait. A locked keychain can still raise a
/// SecurityAgent dialog on the lookup — the probe just never waits on it:
/// the call lives on a side thread and reports BLOCKED once
/// `PROBE_TIMEOUT` passes. The bound covers only the probe: ops after an
/// `Available` verdict assume a probed-available store on a dev host — a
/// lock landing between the probe and a later `set_secret` can still park.
fn probe_store(kind: StoreKind) -> Probe {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let probe_ref =
            SecretRef::parse(&format!("keyring:{TEST_NAMESPACE}/probe")).expect("probe ref parses");
        let outcome = native_store(kind, TEST_NAMESPACE)
            .and_then(|store| store.occupied(&probe_ref).map(|_| store));
        match tx.send(outcome) {
            Ok(()) | Err(_) => {}
        }
    });
    match rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(Ok(store)) => Probe::Available(store),
        Ok(Err(err)) => Probe::Unavailable(err),
        Err(mpsc::RecvTimeoutError::Timeout) => Probe::Blocked,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Probe::Unavailable(ProviderError::StoreUnavailable {
                store: kind,
                reason: "probe thread exited without a verdict".to_string(),
            })
        }
    }
}

/// Every namespaced case gates on the same probe: available → run the real
/// legs; otherwise journal + report the honest status and skip the store
/// legs (the store itself is absent, not the proof).
fn keychain_or_report(case: &str, journal: &mut AuthJournal) -> Option<FlightedStore> {
    match probe_store(StoreKind::Keychain) {
        Probe::Available(store) => Some(store),
        Probe::Unavailable(err) => {
            eprintln!(
                "{case}: keychain probe unavailable: {}",
                error_variant(&err)
            );
            journal.record(
                "probe",
                case,
                TEST_NAMESPACE,
                &format!("blocked: {}", error_verdict(&err)),
            );
            journal.record("status", case, TEST_NAMESPACE, "blocked");
            None
        }
        Probe::Blocked => {
            eprintln!("{case}: keychain probe timed out");
            journal.record("probe", case, TEST_NAMESPACE, "blocked: probe timeout");
            journal.record("status", case, TEST_NAMESPACE, "blocked");
            None
        }
    }
}

/// Whether `account` is a scope path under `service` — the only
/// store-returned specifier the census may journal verbatim. A non-scope
/// answer records as a fingerprint, never as unvalidated platform text.
fn scope_shaped(service: &str, account: &str) -> bool {
    SecretRef::parse(&format!("keyring:{account}")).is_ok_and(|parsed| parsed.service() == service)
}

/// DEC-002 precheck before the first write: journal a namespace census
/// (report-only — a concurrent case owns its own entries), then reap only
/// this case's planned scopes when a crashed prior run left them occupied.
/// Deletes never reach outside `planned`; a still-occupied slot surfaces as
/// `CredentialOccupied` at `login`, so a collision fails before any write.
/// Returns the census exactly as the store answered it, so a case asserts
/// on its own observation instead of the shared journal's rows.
fn precheck(
    store: &FlightedStore,
    planned: &[&SecretRef],
    journal: &mut AuthJournal,
) -> Vec<String> {
    let census = match store.entry_accounts(TEST_NAMESPACE) {
        Ok(accounts) => {
            for account in &accounts {
                let boundary_id = if scope_shaped(TEST_NAMESPACE, account) {
                    account.clone()
                } else {
                    format!(
                        "unscoped sha256:{}",
                        support::sha256_hex(account.as_bytes())
                    )
                };
                journal.record("census", &boundary_id, TEST_NAMESPACE, "observed");
            }
            journal.record(
                "census",
                TEST_NAMESPACE,
                TEST_NAMESPACE,
                &format!("{} entries", accounts.len()),
            );
            accounts
        }
        Err(err) => {
            journal.record(
                "census",
                TEST_NAMESPACE,
                TEST_NAMESPACE,
                &format!("err: {}", error_verdict(&err)),
            );
            Vec::new()
        }
    };
    for &credential in planned {
        match store.occupied(credential) {
            Ok(true) => {
                store
                    .revoke(credential)
                    .unwrap_or_else(|e| panic!("reap own stale entry: {}", error_variant(&e)));
                journal.record("reap", credential.raw(), TEST_NAMESPACE, "deleted stale");
            }
            Ok(false) => journal.record("precheck", credential.raw(), TEST_NAMESPACE, "clear"),
            Err(err) => {
                journal.record(
                    "precheck",
                    credential.raw(),
                    TEST_NAMESPACE,
                    &format!("err: {}", error_verdict(&err)),
                );
            }
        }
    }
    census
}

/// One full lifecycle leg: login → resolve → refresh → resolve → revoke →
/// resolve-absent → login → logout → resolve-absent.
fn lifecycle_leg(store: &FlightedStore, credential: &SecretRef, journal: &mut AuthJournal) {
    let first = format!("{SECRET_CANARY}-{}", credential.profile());
    let second = format!("{first}-rotated");
    store
        .login(credential, first.as_bytes())
        .unwrap_or_else(|e| panic!("login enrolls: {}", error_variant(&e)));
    journal.record(
        "login",
        credential.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(first.as_bytes())),
    );
    let resolved = store
        .resolve(credential)
        .unwrap_or_else(|e| panic!("resolve: {}", error_variant(&e)));
    journal.record(
        "resolve",
        credential.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(&resolved)),
    );
    assert_eq!(
        resolved,
        first.as_bytes(),
        "resolve returns exactly the enrolled bytes"
    );
    store
        .refresh(credential, second.as_bytes())
        .unwrap_or_else(|e| panic!("refresh overwrites: {}", error_variant(&e)));
    journal.record(
        "refresh",
        credential.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(second.as_bytes())),
    );
    let resolved = store
        .resolve(credential)
        .unwrap_or_else(|e| panic!("resolve: {}", error_variant(&e)));
    journal.record(
        "resolve",
        credential.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(&resolved)),
    );
    assert_eq!(
        resolved,
        second.as_bytes(),
        "resolve returns the rotated bytes"
    );
    store
        .revoke(credential)
        .unwrap_or_else(|e| panic!("revoke deletes: {}", error_variant(&e)));
    journal.record("revoke", credential.raw(), TEST_NAMESPACE, "ok");
    match store.resolve(credential) {
        Err(err @ ProviderError::CredentialAbsent { .. }) => journal.record(
            "resolve",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        other => panic!(
            "revoked scope resolves to CredentialAbsent, got {}",
            outcome_variant(&other)
        ),
    }
    store
        .login(credential, first.as_bytes())
        .unwrap_or_else(|e| panic!("re-enroll after revoke: {}", error_variant(&e)));
    store
        .logout(credential)
        .unwrap_or_else(|e| panic!("logout deletes: {}", error_variant(&e)));
    journal.record("logout", credential.raw(), TEST_NAMESPACE, "ok");
    match store.resolve(credential) {
        Err(err @ ProviderError::CredentialAbsent { .. }) => journal.record(
            "resolve",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        other => panic!(
            "logged-out scope resolves to CredentialAbsent, got {}",
            outcome_variant(&other)
        ),
    }
    assert!(
        !store
            .occupied(credential)
            .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
        "scope is empty after logout"
    );
}

// ----- store lifecycle -------------------------------------------------

/// AC: login/refresh/revoke/logout roundtrip on the real store seam for
/// every admitted auth class — the one seam serves all eight connection
/// IDs, so each class leg exercises the same native lifecycle.
#[test]
fn credential_lifecycle_login_refresh_revoke_logout_roundtrips_on_the_store_seam() {
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let mut journal = AuthJournal::open("lifecycle");
    let Some(store) = keychain_or_report("lifecycle", &mut journal) else {
        return;
    };
    for class in AUTH_CLASSES {
        let credential = scoped_ref(&format!("lifecycle-{class}"));
        precheck(&store, &[&credential], &mut journal);
        lifecycle_leg(&store, &credential, &mut journal);
        journal.record("lifecycle", credential.raw(), TEST_NAMESPACE, "pass");
    }
}

/// INV: a neighbor profile's bytes are untouched by another profile's full
/// lifecycle — writes are scoped by account/origin/profile, never by
/// namespace-wide mutation.
#[test]
fn neighbor_profile_is_byte_identical_after_another_profiles_lifecycle() {
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let mut journal = AuthJournal::open("neighbor");
    let Some(store) = keychain_or_report("neighbor", &mut journal) else {
        return;
    };
    let subject = scoped_ref("neighbor-subject");
    let control = scoped_ref("neighbor-control");
    precheck(&store, &[&subject, &control], &mut journal);
    let control_secret = b"control-material-9f3ac2";
    store
        .login(&control, control_secret)
        .unwrap_or_else(|e| panic!("control enrolls: {}", error_variant(&e)));
    let before = store
        .resolve(&control)
        .unwrap_or_else(|e| panic!("control resolves: {}", error_variant(&e)));
    journal.record(
        "resolve",
        control.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(&before)),
    );
    lifecycle_leg(&store, &subject, &mut journal);
    let after = store
        .resolve(&control)
        .unwrap_or_else(|e| panic!("control still resolves: {}", error_variant(&e)));
    journal.record(
        "resolve",
        control.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(&after)),
    );
    assert_eq!(before, control_secret, "control holds its own bytes");
    assert_eq!(
        after, before,
        "neighbor bytes are identical after another profile's lifecycle"
    );
    store
        .revoke(&control)
        .unwrap_or_else(|e| panic!("control teardown: {}", error_variant(&e)));
    journal.record("teardown", control.raw(), TEST_NAMESPACE, "ok");
    assert!(
        !store
            .occupied(&control)
            .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
        "control scope empty after teardown"
    );
}

/// The named create/delete leg: entries under `rivect-test` are created by
/// this test and deleted by this test; the precheck census + reap ran
/// before the first write and the journal on disk records it.
#[test]
fn keychain_rivect_test_namespaced_entries_are_created_and_deleted_by_the_test() {
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let mut journal = AuthJournal::open("namespaced");
    let Some(store) = keychain_or_report("namespaced", &mut journal) else {
        return;
    };
    let credential = scoped_ref("namespaced-entry");
    precheck(&store, &[&credential], &mut journal);
    let secret = format!("{SECRET_CANARY}-namespaced");
    store
        .login(&credential, secret.as_bytes())
        .unwrap_or_else(|e| panic!("test creates the entry: {}", error_variant(&e)));
    journal.record("create", credential.raw(), TEST_NAMESPACE, "created");
    assert!(
        store
            .occupied(&credential)
            .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
        "the entry the test created is visible"
    );
    store
        .revoke(&credential)
        .unwrap_or_else(|e| panic!("test deletes the entry: {}", error_variant(&e)));
    journal.record("delete", credential.raw(), TEST_NAMESPACE, "deleted");
    assert!(
        !store
            .occupied(&credential)
            .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
        "the entry the test deleted is gone"
    );
    let journal_on_disk = journal_text();
    assert!(
        journal_on_disk.contains("\"op\":\"census\""),
        "the journal recorded the precheck before the first write"
    );
    assert!(
        journal_on_disk.contains("\"boundary_id\":\"keyring:rivect-test/namespaced-entry\""),
        "the journal records this case's boundary id"
    );
    assert!(
        !journal_on_disk.contains(&secret),
        "the journal never contains secret bytes"
    );
}

/// A ref outside the admitted namespace — or aimed at another store class —
/// is refused before any store call: every op answers
/// `CredentialOutsideNamespace` and no entry is created. The ref/class
/// guards run inside `entry()`, ahead of any store contact, so a scripted
/// backend proves them on every host; only the held-scope legs need a
/// live store.
#[test]
fn a_foreign_prefix_collision_fails_before_any_write() {
    let mut journal = AuthJournal::open("collision");
    let guarding = KeyringBackend::new(
        Arc::new(ScriptedStore {
            script: Script::Absent,
        }),
        StoreKind::Keychain,
        TEST_NAMESPACE,
    );
    let foreign =
        SecretRef::parse("keyring:other-vendor/someone-elses-entry").expect("foreign ref parses");
    let wrong_class = SecretRef::parse("secret-service:rivect-test/foreign-class")
        .expect("cross-class ref parses");
    for credential in [&foreign, &wrong_class] {
        for op in [
            guarding.occupied(credential).map(|_| ()),
            guarding.resolve(credential).map(|_| ()),
            guarding.login(credential, b"never-written"),
            guarding.refresh(credential, b"never-written"),
            guarding.revoke(credential),
            guarding.logout(credential),
        ] {
            assert!(
                matches!(op, Err(ProviderError::CredentialOutsideNamespace { .. })),
                "foreign scope is refused before any store call: {}",
                outcome_variant(&op)
            );
        }
        journal.record(
            "guard",
            credential.raw(),
            TEST_NAMESPACE,
            "denied before write",
        );
    }
    // A foreign service census is refused before any store call, too.
    assert!(
        matches!(
            guarding.entry_accounts("other-vendor"),
            Err(ProviderError::CredentialOutsideNamespace { .. })
        ),
        "a foreign-service census is denied before any store call"
    );
    // Same-slot collision inside the namespace: login on an occupied scope
    // fails as CredentialOccupied before touching the stored bytes. The
    // occupancy check reads live state, so this leg waits on a real store.
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let Some(store) = keychain_or_report("collision", &mut journal) else {
        return;
    };
    let held = scoped_ref("collision-held");
    precheck(&store, &[&held], &mut journal);
    store
        .login(&held, b"held")
        .unwrap_or_else(|e| panic!("first enroll wins: {}", error_variant(&e)));
    assert!(
        matches!(
            store.login(&held, b"clobber-attempt"),
            Err(ProviderError::CredentialOccupied { .. })
        ),
        "an occupied slot refuses overwrite before any write"
    );
    let held_bytes = store
        .resolve(&held)
        .unwrap_or_else(|e| panic!("resolve: {}", error_variant(&e)));
    journal.record(
        "resolve",
        held.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(&held_bytes)),
    );
    assert_eq!(
        held_bytes,
        b"held".as_slice(),
        "the occupant's bytes are untouched"
    );
    store
        .revoke(&held)
        .unwrap_or_else(|e| panic!("teardown: {}", error_variant(&e)));
}

/// INV-006: a store class with no usable backend on this platform is a
/// named typed error; backend-level ambiguity and denial map to
/// `StoreAmbiguous`/`StoreUnavailable`. No leg ever falls back to
/// plaintext.
#[test]
fn unavailable_or_ambiguous_store_returns_a_named_typed_error_without_plaintext_fallback() {
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let mut journal = AuthJournal::open("store-errors");
    // Platform-absent backend: the Secret Service class exists only where a
    // D-Bus session store can answer.
    match native_store(StoreKind::SecretService, TEST_NAMESPACE) {
        Err(
            err @ ProviderError::StoreUnavailable {
                store: StoreKind::SecretService,
                ..
            },
        ) => journal.record(
            "unavailable",
            "store-errors",
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        Err(other) => panic!("expected StoreUnavailable, got {}", error_variant(&other)),
        Ok(store) => {
            // A Linux host with a live session store — the class is
            // available, which is also a correct verdict.
            assert_eq!(
                store.kind(),
                StoreKind::SecretService,
                "a live Secret Service backend reports its own class"
            );
        }
    }

    // Backend-level mapping through the real KeyringBackend: a store that
    // answers Ambiguous / NoStorageAccess / NoEntry maps to the named
    // variants — never silently, never to plaintext.
    let ambiguous = KeyringBackend::new(
        Arc::new(ScriptedStore {
            script: Script::Ambiguous,
        }),
        StoreKind::Keychain,
        TEST_NAMESPACE,
    );
    let credential = keychain_ref("ambiguous-target");
    match ambiguous.resolve(&credential) {
        Err(
            err @ ProviderError::StoreAmbiguous {
                store: StoreKind::Keychain,
            },
        ) => journal.record(
            "ambiguous",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        other => panic!(
            "an ambiguous native answer is a named typed error, got {}",
            outcome_variant(&other)
        ),
    }
    match ambiguous.login(&credential, b"material") {
        Err(err @ ProviderError::StoreAmbiguous { .. }) => journal.record(
            "ambiguous",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        other => panic!(
            "ambiguity fails before any write, got {}",
            outcome_variant(&other)
        ),
    }

    let denied = KeyringBackend::new(
        Arc::new(ScriptedStore {
            script: Script::Denied("scripted: storage access denied".to_string()),
        }),
        StoreKind::Keychain,
        TEST_NAMESPACE,
    );
    match denied.resolve(&credential) {
        Err(
            err @ ProviderError::StoreUnavailable {
                store: StoreKind::Keychain,
                ..
            },
        ) => journal.record(
            "unavailable",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        other => panic!(
            "a denied native answer is StoreUnavailable, got {}",
            outcome_variant(&other)
        ),
    }

    let absent = KeyringBackend::new(
        Arc::new(ScriptedStore {
            script: Script::Absent,
        }),
        StoreKind::Keychain,
        TEST_NAMESPACE,
    );
    match absent.resolve(&credential) {
        Err(err @ ProviderError::CredentialAbsent { .. }) => journal.record(
            "resolve",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("err: {}", error_verdict(&err)),
        ),
        other => panic!(
            "a missing entry is CredentialAbsent, not an implicit empty, got {}",
            outcome_variant(&other)
        ),
    }
    assert!(
        !absent
            .occupied(&credential)
            .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
        "absent reads as unoccupied"
    );
}

/// A locked or absent login keychain records an honest status inside a
/// bounded wait — typed error or BLOCKED, never a modal prompt stalling
/// the probe. When the store answers, the precheck's stale-entry reap runs
/// for real: a `rivect-test` entry planted at a planned scope is reported
/// and deleted, while an unplanned entry stays untouched. Post-probe ops
/// run unbounded on the test thread — they assume a probed-available store
/// on a dev host, so a lock landing after the probe can still park an op.
#[test]
fn keychain_store_absent_or_locked_records_honest_status_without_hanging() {
    let case = "keychain-probe";
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let mut journal = AuthJournal::open(case);
    match probe_store(StoreKind::Keychain) {
        Probe::Available(store) => {
            journal.record("probe", case, TEST_NAMESPACE, "available");
            // Stale-entry reap (DEC-002): an entry a crashed prior run
            // left at a planned scope reads occupied, the precheck reaps
            // it inside the rivect-test boundary, and an unplanned
            // neighbor is untouched.
            let stale = scoped_ref("probe-stale");
            let unplanned = scoped_ref("probe-unplanned");
            for entry in [&stale, &unplanned] {
                // Clear a crashed-run remnant first — absent is the norm.
                let _ = store.revoke(entry);
                store
                    .login(entry, b"planted")
                    .unwrap_or_else(|e| panic!("plant entry: {}", error_variant(&e)));
            }
            assert!(
                store
                    .occupied(&stale)
                    .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
                "the stale entry reads occupied before the reap"
            );
            let census = precheck(&store, &[&stale], &mut journal);
            assert!(
                !store
                    .occupied(&stale)
                    .unwrap_or_else(|e| panic!("occupied reads: {}", error_variant(&e))),
                "the precheck reaped the stale entry"
            );
            let planted = store
                .resolve(&unplanned)
                .unwrap_or_else(|e| panic!("unplanned resolves: {}", error_variant(&e)));
            journal.record(
                "resolve",
                unplanned.raw(),
                TEST_NAMESPACE,
                &format!("ok sha256:{}", support::sha256_hex(&planted)),
            );
            assert_eq!(
                planted,
                b"planted".as_slice(),
                "an unplanned entry is outside the delete-only-rivect-test reap path"
            );
            store
                .revoke(&unplanned)
                .unwrap_or_else(|e| panic!("teardown unplanned: {}", error_variant(&e)));
            // The census assertion anchors on this case's own census
            // observation: the shared journal could satisfy a
            // `boundary_id` filter with any concurrent case's rows, and
            // an enumerate-all `search` can transiently miss a fresh
            // entry under parallel mutation.
            assert!(
                census.iter().any(|account| account == stale.scope()),
                "the precheck census observed the stale entry at its scope"
            );
            let rows = journal_rows();
            assert!(
                rows.iter().any(|row| row["op"] == "reap"
                    && row["boundary_id"] == stale.raw()
                    && row["namespace"] == TEST_NAMESPACE),
                "the precheck journal recorded the reap inside the rivect-test boundary"
            );
        }
        Probe::Unavailable(err) => {
            eprintln!(
                "{case}: keychain probe unavailable: {}",
                error_variant(&err)
            );
            journal.record(
                "probe",
                case,
                TEST_NAMESPACE,
                &format!("blocked: {}", error_verdict(&err)),
            );
        }
        Probe::Blocked => {
            eprintln!("{case}: keychain probe timed out");
            journal.record("probe", case, TEST_NAMESPACE, "blocked: probe timeout");
        }
    }
    // Whatever the probe answered, this case journaled exactly one verdict
    // from the honest set — never silence, never a hang.
    let probes: Vec<Value> = journal_rows()
        .into_iter()
        .filter(|row| row["op"] == "probe" && row["boundary_id"] == case)
        .collect();
    assert_eq!(
        probes.len(),
        1,
        "this case records exactly one probe verdict"
    );
    let verdict = probes[0]["result"].as_str().expect("verdict is a string");
    assert!(
        ["available", "blocked", "not-run"]
            .iter()
            .any(|v| verdict.starts_with(v)),
        "the probe verdict is an honest status: {verdict}"
    );
}

/// Linux leg: where no Secret Service session store answers, the status is
/// NOT_RUN with the named typed error — the plaintext substitute path does
/// not exist. The store-touching calls ride a side thread under the same
/// bound as the keychain probe: where a store does answer but a collection
/// is locked, `search`/`get_secret` can park on an unlock prompt, so the
/// leg reports BLOCKED instead of hanging the suite on a modal dialog.
#[test]
fn secret_service_leg_records_not_run_when_the_headless_store_is_absent() {
    let case = "secret-service";
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let journal = AuthJournal::open(case);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut journal = journal;
        match native_store(StoreKind::SecretService, TEST_NAMESPACE) {
            Ok(store) => {
                let credential = scoped_ref("secret-service-lifecycle");
                precheck(&store, &[&credential], &mut journal);
                lifecycle_leg(&store, &credential, &mut journal);
                journal.record("lifecycle", credential.raw(), TEST_NAMESPACE, "pass");
            }
            Err(err @ ProviderError::StoreUnavailable { .. }) => {
                eprintln!(
                    "{case}: secret-service leg not run: {}",
                    error_variant(&err)
                );
                journal.record(
                    "probe",
                    case,
                    TEST_NAMESPACE,
                    &format!("not-run: {}", error_verdict(&err)),
                );
            }
            Err(other) => panic!("expected StoreUnavailable, got {}", error_variant(&other)),
        }
        match tx.send(()) {
            Ok(()) | Err(_) => {}
        }
    });
    match rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(()) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {
            eprintln!("{case}: secret-service leg timed out");
            // The wedged leg keeps the moved journal; a fresh instance
            // records the honest verdict on the same bounded file.
            let mut journal = AuthJournal::open(case);
            journal.record("probe", case, TEST_NAMESPACE, "blocked: leg timeout");
            journal.record("status", case, TEST_NAMESPACE, "blocked");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{case}: leg thread exited without a verdict")
        }
    }
}

/// The consumptive-gate collision proof: a mutant journal that aliases
/// two distinct ops onto one `(seam, boundary_id)` evidence identity is
/// rejected — one retained fingerprint must identify exactly one emit
/// site (one-shot-actions §6). Distinct seams may legitimately share a
/// boundary id — a lifecycle leg records precheck, resolve and revoke on
/// one scope — and the live journal validates under the same map.
#[test]
fn a_mutant_aliasing_two_seams_to_one_fingerprint_is_rejected() {
    let mut journal = AuthJournal::open("boundary-map");
    let mutant = |op: &str, boundary_id: &str| {
        json!({
            "op": op,
            "boundary_id": boundary_id,
            "namespace": TEST_NAMESPACE,
            "result": "ok",
        })
    };

    // Positive control: three different seams on one boundary id keep
    // distinct evidence identities — the shape every lifecycle leg
    // produces honestly.
    let boundary = "keyring:rivect-test/mutant-boundary";
    let disjoint = [
        mutant("precheck", boundary),
        mutant("resolve", boundary),
        mutant("delete", boundary),
    ];
    check_boundary_map(&disjoint)
        .unwrap_or_else(|e| panic!("distinct seams on one boundary stay attributable: {e}"));

    // `precheck` and `census` both emit on AUTH-KC-PRECHECK: on one
    // boundary id their rows are interchangeable evidence, so a census
    // row could satisfy the precheck seam's assertion.
    let aliased_precheck = [mutant("precheck", boundary), mutant("census", boundary)];
    let verdict = check_boundary_map(&aliased_precheck);
    assert!(
        verdict.is_err(),
        "two ops aliased to one seam fingerprint must be rejected: {aliased_precheck:?}"
    );

    // Same aliasing on the create and delete seams — a `login` row
    // satisfying the namespaced `create` assertion, a `teardown` row
    // satisfying `delete`.
    for aliased in [
        [mutant("create", boundary), mutant("login", boundary)],
        [mutant("delete", boundary), mutant("teardown", boundary)],
        [mutant("precheck", boundary), mutant("reap", boundary)],
    ] {
        assert!(
            check_boundary_map(&aliased).is_err(),
            "aliased ops on one boundary must be rejected: {aliased:?}"
        );
    }

    // The vocabulary is closed: an op outside the map is rejected before
    // any seam reasoning, and every planned seam has a real emit site.
    let unknown = [mutant("wipe", boundary)];
    assert!(
        check_boundary_map(&unknown).is_err(),
        "an op outside the boundary map must be rejected"
    );
    for (op, seam) in [
        ("precheck", "AUTH-KC-PRECHECK"),
        ("create", "AUTH-KC-CREATE"),
        ("resolve", "AUTH-KC-READ"),
        ("delete", "AUTH-KC-DELETE"),
        ("unavailable", "AUTH-STORE-UNAVAILABLE"),
        ("ambiguous", "AUTH-STORE-AMBIGUOUS"),
    ] {
        assert_eq!(seam_of(op), Some(seam), "the map pins op {op} to {seam}");
    }

    // The live journal under the same validator: every row the suite
    // emitted this run carries a mapped op and never aliases — read-only,
    // the journal file itself is untouched.
    check_boundary_map(&journal_rows())
        .unwrap_or_else(|e| panic!("live journal violates the boundary map: {e}"));
    journal.record("status", "boundary-map", TEST_NAMESPACE, "pass");
}

// ----- serialization ---------------------------------------------------

/// What the scripted release channel delivers to a parked `refresh`.
enum Release {
    /// Complete the write and return `Ok`.
    Commit,
    /// Return the error without writing — a failed leader publishes its
    /// own `Err` to every joiner.
    Fail(ProviderError),
    /// Panic inside the op — the leader-panic path that must still
    /// deregister the flight and wake every joiner.
    Panic,
}

/// Inner store that counts `refresh` ops and parks the leader on a release
/// channel — the test controls exactly when the in-flight op completes.
struct CountingStore {
    calls: AtomicU64,
    release: Mutex<mpsc::Receiver<Release>>,
    written: Mutex<HashMap<String, Vec<u8>>>,
}

impl CredentialStore for CountingStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        Ok(self
            .written
            .lock()
            .expect("map")
            .contains_key(credential.scope()))
    }

    fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
        Ok(Vec::new())
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.written
            .lock()
            .expect("map")
            .insert(credential.scope().to_string(), secret.to_vec());
        Ok(())
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.written
            .lock()
            .expect("map")
            .get(credential.scope())
            .cloned()
            .ok_or_else(|| ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // The gate guard must drop before the scripted outcome runs — a
        // `Panic` release would otherwise poison the channel mutex and
        // break the recovery leg, not the panic path under test.
        let release = self
            .release
            .lock()
            .expect("gate")
            .recv()
            .expect("release channel open");
        match release {
            Release::Commit => {
                self.written
                    .lock()
                    .expect("map")
                    .insert(credential.scope().to_string(), secret.to_vec());
                Ok(())
            }
            Release::Fail(err) => Err(err),
            Release::Panic => panic!("scripted leader panic"),
        }
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.written.lock().expect("map").remove(credential.scope());
        Ok(())
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// INV-009: while one profile's refresh is in flight, every other refresh
/// for the same profile joins it — one inner store op total. A different
/// profile flies independently; a refresh after the flight is a new op. A
/// failing leader hands every joiner its own `Err`; a panicking leader
/// still deregisters the flight, wakes joiners with `StoreUnavailable`,
/// and leaves the scope open to the next leader.
#[test]
fn concurrent_refresh_on_one_profile_serializes_to_a_single_in_flight_operation() {
    let (release_tx, release_rx) = mpsc::channel();
    let inner = Arc::new(CountingStore {
        calls: AtomicU64::new(0),
        release: Mutex::new(release_rx),
        written: Mutex::new(HashMap::new()),
    });
    let store = Arc::new(FlightedStore::new(Box::new(CountingStoreAdapter {
        inner: Arc::clone(&inner),
    })));
    let credential = keychain_ref("race-profile");

    // Leader enters the inner op and parks on the release channel.
    let leader = {
        let store = Arc::clone(&store);
        let credential = credential.clone();
        std::thread::spawn(move || store.refresh(&credential, b"leader-bytes"))
    };
    wait_until_eq(|| inner.calls.load(Ordering::SeqCst), 1);

    // Followers join the registered flight — `refresh_waiters` proves each
    // is parked inside the seam before the leader may complete.
    const FOLLOWERS: usize = 8;
    let followers: Vec<_> = (0..FOLLOWERS)
        .map(|i| {
            let store = Arc::clone(&store);
            let credential = credential.clone();
            std::thread::spawn(move || {
                store.refresh(&credential, format!("follower-{i}").as_bytes())
            })
        })
        .collect();
    wait_until_eq(|| store.refresh_waiters(), FOLLOWERS as u64);

    // A foreign-class ref naming the same scope is refused while the
    // leader still holds the flight — the kind guard runs before slot
    // selection, so the refusal returns at once and never parks as a
    // waiter.
    let foreign = SecretRef::parse(&format!("secret-service:{}", credential.scope()))
        .expect("foreign ref parses");
    let foreign_joiner = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.refresh(&foreign, b"foreign-bytes"))
    };
    let foreign_outcome =
        join_bounded(foreign_joiner).expect("foreign-class refresh thread did not panic");
    assert!(
        matches!(
            foreign_outcome,
            Err(ProviderError::CredentialOutsideNamespace {
                store: StoreKind::Keychain,
                ..
            })
        ),
        "a foreign-class ref is refused while a same-scope flight is parked: {}",
        outcome_variant(&foreign_outcome)
    );
    assert_eq!(
        store.refresh_waiters(),
        FOLLOWERS as u64,
        "a refused ref never parks on the flight"
    );

    release_tx
        .send(Release::Commit)
        .expect("release the leader");
    for handle in std::iter::once(leader).chain(followers) {
        join_bounded(handle)
            .expect("refresh thread did not panic")
            .unwrap_or_else(|e| panic!("refresh ok: {}", error_variant(&e)));
    }
    assert_eq!(
        inner.calls.load(Ordering::SeqCst),
        1,
        "N concurrent same-profile refreshes coalesce to one inner op"
    );
    assert_eq!(
        inner
            .resolve(&credential)
            .as_deref()
            .unwrap_or_else(|e| panic!("resolve: {}", error_variant(e))),
        b"leader-bytes".as_slice(),
        "the joined outcome is the leader's write"
    );

    // A refresh after the flight closed is its own inner op — it consumes
    // one release like every inner op.
    release_tx
        .send(Release::Commit)
        .expect("release next-flight");
    store
        .refresh(&credential, b"next-flight")
        .unwrap_or_else(|e| panic!("refresh: {}", error_variant(&e)));
    assert_eq!(inner.calls.load(Ordering::SeqCst), 2);

    // A different profile is a different flight — no cross-profile
    // serialization.
    let other = keychain_ref("race-other");
    let second = {
        let store = Arc::clone(&store);
        let other = other.clone();
        std::thread::spawn(move || store.refresh(&other, b"other-bytes"))
    };
    wait_until_eq(|| inner.calls.load(Ordering::SeqCst), 3);
    let third = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.refresh(&credential, b"third"))
    };
    wait_until_eq(|| inner.calls.load(Ordering::SeqCst), 4);
    release_tx.send(Release::Commit).expect("release second");
    release_tx.send(Release::Commit).expect("release third");
    join_bounded(second)
        .expect("refresh thread did not panic")
        .unwrap_or_else(|e| panic!("refresh ok: {}", error_variant(&e)));
    join_bounded(third)
        .expect("refresh thread did not panic")
        .unwrap_or_else(|e| panic!("refresh ok: {}", error_variant(&e)));
    assert_eq!(
        inner.calls.load(Ordering::SeqCst),
        4,
        "distinct profiles refresh in independent flights"
    );

    // A failing leader publishes its own `Err`: the joiner gets that
    // outcome verbatim — never a retry, never a fabricated `Ok`.
    let fail_ref = keychain_ref("race-fail");
    let failed_leader = {
        let store = Arc::clone(&store);
        let fail_ref = fail_ref.clone();
        std::thread::spawn(move || store.refresh(&fail_ref, b"leader-bytes"))
    };
    wait_until_eq(|| inner.calls.load(Ordering::SeqCst), 5);
    let failed_joiner = {
        let store = Arc::clone(&store);
        let fail_ref = fail_ref.clone();
        std::thread::spawn(move || store.refresh(&fail_ref, b"joiner-bytes"))
    };
    wait_until_eq(|| store.refresh_waiters(), 1);
    let scripted = ProviderError::StoreUnavailable {
        store: StoreKind::Keychain,
        reason: "scripted leader failure".to_string(),
    };
    release_tx
        .send(Release::Fail(scripted.clone()))
        .expect("release failing leader");
    let leader_outcome = join_bounded(failed_leader).expect("leader thread did not panic");
    let joiner_outcome = join_bounded(failed_joiner).expect("joiner thread did not panic");
    assert!(
        matches!(leader_outcome, Err(ProviderError::StoreUnavailable { .. })),
        "the failed leader returns its own error: {}",
        outcome_variant(&leader_outcome)
    );
    assert!(
        leader_outcome == joiner_outcome,
        "a joiner receives the leader's outcome verbatim: {} vs {}",
        outcome_variant(&leader_outcome),
        outcome_variant(&joiner_outcome)
    );
    assert!(
        matches!(
            inner.resolve(&fail_ref),
            Err(ProviderError::CredentialAbsent { .. })
        ),
        "a failed leader wrote nothing for the joiner to inherit"
    );

    // A panicking leader still deregisters the flight and wakes the
    // joiner with StoreUnavailable; the next refresh on the scope is a
    // fresh leader — no permanent wedge.
    let panic_ref = keychain_ref("race-panic");
    let panicking = {
        let store = Arc::clone(&store);
        let panic_ref = panic_ref.clone();
        std::thread::spawn(move || store.refresh(&panic_ref, b"leader-bytes"))
    };
    wait_until_eq(|| inner.calls.load(Ordering::SeqCst), 6);
    let parked_joiner = {
        let store = Arc::clone(&store);
        let panic_ref = panic_ref.clone();
        std::thread::spawn(move || store.refresh(&panic_ref, b"joiner-bytes"))
    };
    wait_until_eq(|| store.refresh_waiters(), 1);
    release_tx
        .send(Release::Panic)
        .expect("release panicking leader");
    assert!(
        join_bounded(panicking).is_err(),
        "the leader thread carries the panic"
    );
    let joined = join_bounded(parked_joiner).expect("joiner thread did not panic");
    match joined {
        // `reason` is verbatim platform text — pin it in the pattern so a
        // mismatch panics with the variant, never the platform string.
        Err(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason,
        }) if reason == "refresh leader panicked" => {}
        other => panic!(
            "a parked joiner must observe the panic outcome, got {}",
            outcome_variant(&other)
        ),
    }
    assert_eq!(
        store.refresh_waiters(),
        0,
        "no waiter is left parked on a dead flight"
    );
    release_tx
        .send(Release::Commit)
        .expect("release the next leader");
    store.refresh(&panic_ref, b"recovered").unwrap_or_else(|e| {
        panic!(
            "refresh after a leader panic is a fresh leader, not a wedge: {}",
            error_variant(&e)
        )
    });
    assert_eq!(
        inner
            .resolve(&panic_ref)
            .as_deref()
            .unwrap_or_else(|e| panic!("resolve: {}", error_variant(e))),
        b"recovered".as_slice(),
        "the next leader writes normally after a leader panic"
    );
    assert_eq!(inner.calls.load(Ordering::SeqCst), 7);
}

/// A joiner parked behind a wedged leader cannot wait on the leader's
/// synchronous store call — the join bound releases it with a typed
/// `StoreUnavailable` instead. The flight stays the leader's to finish:
/// the leader's write still lands and the next refresh on the scope is
/// a fresh leader.
#[test]
fn refresh_join_on_a_wedged_leader_denies_within_the_join_bound() {
    const JOIN_BOUND: Duration = Duration::from_millis(250);
    let (release_tx, release_rx) = mpsc::channel();
    let inner = Arc::new(CountingStore {
        calls: AtomicU64::new(0),
        release: Mutex::new(release_rx),
        written: Mutex::new(HashMap::new()),
    });
    let store = Arc::new(FlightedStore::with_join_bound(
        Box::new(CountingStoreAdapter {
            inner: Arc::clone(&inner),
        }),
        JOIN_BOUND,
    ));
    let credential = keychain_ref("bounded-join");

    // Leader enters the inner op and parks on the release channel.
    let leader = {
        let store = Arc::clone(&store);
        let credential = credential.clone();
        std::thread::spawn(move || store.refresh(&credential, b"leader-bytes"))
    };
    wait_until_eq(|| inner.calls.load(Ordering::SeqCst), 1);

    // The joiner parks on the live flight — then the bound, not the
    // leader's release, is what returns its verdict.
    let joiner = {
        let store = Arc::clone(&store);
        let credential = credential.clone();
        std::thread::spawn(move || store.refresh(&credential, b"joiner-bytes"))
    };
    wait_until_eq(|| store.refresh_waiters(), 1);
    let started = std::time::Instant::now();
    let outcome = join_bounded(joiner).expect("joiner thread did not panic");
    assert!(
        started.elapsed() < PROBE_TIMEOUT,
        "the join bound released the joiner, not the leader's wedge: {:?}",
        started.elapsed()
    );
    match outcome {
        Err(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason,
        }) if reason == "refresh join exceeded its bound" => {}
        other => panic!(
            "a wedged flight denies its joiner typed: {}",
            outcome_variant(&other)
        ),
    }
    assert_eq!(
        store.refresh_waiters(),
        0,
        "a bound-released joiner leaves the waiter count honest"
    );

    // The leader's op was never the joiner's to cancel — it still owns
    // the flight and its write still lands on release.
    release_tx
        .send(Release::Commit)
        .expect("release the wedged leader");
    join_bounded(leader)
        .expect("leader thread did not panic")
        .unwrap_or_else(|e| panic!("leader refresh ok: {}", error_variant(&e)));
    assert_eq!(
        inner
            .resolve(&credential)
            .as_deref()
            .unwrap_or_else(|e| panic!("resolve: {}", error_variant(e))),
        b"leader-bytes".as_slice(),
        "the wedged leader's write lands when its call returns"
    );
    release_tx
        .send(Release::Commit)
        .expect("release the next leader");
    store.refresh(&credential, b"after").unwrap_or_else(|e| {
        panic!(
            "refresh after a bound-denied join is a fresh leader: {}",
            error_variant(&e)
        )
    });
    assert_eq!(
        inner.calls.load(Ordering::SeqCst),
        2,
        "the bound-denied joiner never ran a store op; only leaders did"
    );
}

/// DEC-002 enrollment serialization: threads racing `login` on one scope
/// pass through the per-scope mutex one at a time — exactly one observes
/// the slot empty and writes; the rest get `CredentialOccupied`. The
/// inner `get_secret` announces itself and parks until a release token,
/// so a racer entering the check while the leader is parked would
/// announce a second arrival — none may.
#[test]
fn concurrent_logins_on_one_scope_serialize_to_a_single_enrollment() {
    const RACERS: usize = 4;
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let state = Arc::new(ParkingState {
        arrived: arrived_tx,
        release: Mutex::new(release_rx),
        sets: AtomicU64::new(0),
        written: Mutex::new(HashMap::new()),
    });
    let backend = Arc::new(KeyringBackend::new(
        Arc::new(ParkingStore {
            state: Arc::clone(&state),
        }),
        StoreKind::Keychain,
        TEST_NAMESPACE,
    ));
    let credential = keychain_ref("login-race");

    let racers: Vec<_> = (0..RACERS)
        .map(|i| {
            let backend = Arc::clone(&backend);
            let credential = credential.clone();
            std::thread::spawn(move || backend.login(&credential, format!("racer-{i}").as_bytes()))
        })
        .collect();

    // The leader parks inside its occupancy check; while it holds the
    // scope lock no second check may start — a second arrival would mean
    // the check ran outside the mutex.
    arrived_rx
        .recv_timeout(PROBE_TIMEOUT)
        .expect("a leader entered the occupancy check");
    assert!(
        arrived_rx.recv_timeout(Duration::from_millis(250)).is_err(),
        "a second login entered the occupied check while the leader held the scope lock"
    );
    release_tx.send(()).expect("release the leader");
    // Every later check arrives only after the leader's write landed —
    // the check-then-act is serialized, never interleaved.
    for _ in 1..RACERS {
        arrived_rx
            .recv_timeout(PROBE_TIMEOUT)
            .expect("a queued racer entered the occupancy check");
        assert_eq!(
            state.sets.load(Ordering::SeqCst),
            1,
            "a queued racer's check runs only after the leader's write landed"
        );
        release_tx.send(()).expect("release the racer");
    }

    let outcomes: Vec<_> = racers
        .into_iter()
        .map(|handle| join_bounded(handle).expect("login thread did not panic"))
        .collect();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one racer enrolls"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| { matches!(outcome, Err(ProviderError::CredentialOccupied { .. })) })
            .count(),
        RACERS - 1,
        "every other racer is refused as occupied"
    );
    assert_eq!(
        state.sets.load(Ordering::SeqCst),
        1,
        "exactly one store write ran"
    );
}

/// Wait for a counter to reach a value inside a wall-clock bound — a stuck
/// seam fails with the observed value, not a bare timeout.
fn wait_until_eq(observe: impl Fn() -> u64, expected: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let observed = observe();
        if observed == expected {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "condition not met within the wait bound: expected {expected}, observed {observed}"
        );
        std::thread::yield_now();
    }
}

/// Joins a thread inside a wall-clock bound: the join itself runs on a
/// watchdog thread, so a wedged seam fails the test instead of hanging
/// the suite forever.
fn join_bounded<T: Send + 'static>(handle: std::thread::JoinHandle<T>) -> std::thread::Result<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || match tx.send(handle.join()) {
        Ok(()) | Err(_) => {}
    });
    rx.recv_timeout(PROBE_TIMEOUT)
        .expect("thread finished within the bound")
}

/// Adapter shim: `CountingStore` holds the probes as `Arc` fields; the seam
/// consumes boxed trait objects.
struct CountingStoreAdapter {
    inner: Arc<CountingStore>,
}

impl CredentialStore for CountingStoreAdapter {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.inner.occupied(credential)
    }
    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        self.inner.entry_accounts(service)
    }
    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.login(credential, secret)
    }
    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.inner.resolve(credential)
    }
    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.refresh(credential, secret)
    }
    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.revoke(credential)
    }
    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.logout(credential)
    }
}

// ----- keyring-core scripted backend ------------------------------------

/// The native-error mapping legs drive the real `KeyringBackend` with a
/// keyring-core store whose credentials answer with platform errors.
#[derive(Clone)]
enum Script {
    Ambiguous,
    /// A storage-access denial carrying the platform's own error text —
    /// the leg parameterizes the text so the `map_error` trust boundary
    /// can be pinned against text embedding the canary.
    Denied(String),
    Absent,
}

impl Script {
    fn error(&self) -> keyring_core::Error {
        match self {
            Script::Ambiguous => keyring_core::Error::Ambiguous(Vec::new()),
            Script::Denied(text) => keyring_core::Error::NoStorageAccess(text.clone().into()),
            Script::Absent => keyring_core::Error::NoEntry,
        }
    }
}

struct ScriptedCredential {
    script: Script,
}

impl keyring_core::api::CredentialApi for ScriptedCredential {
    fn set_secret(&self, _secret: &[u8]) -> keyring_core::Result<()> {
        Err(self.script.error())
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        Err(self.script.error())
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        Err(self.script.error())
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::Credential>>> {
        Err(self.script.error())
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((TEST_NAMESPACE.to_string(), "scripted".to_string()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct ScriptedStore {
    script: Script,
}

impl keyring_core::api::CredentialStoreApi for ScriptedStore {
    fn vendor(&self) -> String {
        "test-scripted".to_string()
    }

    fn id(&self) -> String {
        "scripted-store".to_string()
    }

    fn build(
        &self,
        _service: &str,
        _user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        Ok(keyring_core::Entry::new_with_credential(Arc::new(
            ScriptedCredential {
                script: self.script.clone(),
            },
        )))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Shared state behind [`ParkingStore`] entries: `arrived` announces each
/// `get_secret`, `release` parks it until the test sends one token, and
/// `written`/`sets` record the writes the check gates on.
struct ParkingState {
    arrived: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    sets: AtomicU64,
    written: Mutex<HashMap<String, Vec<u8>>>,
}

/// A keyring-core backend whose `get_secret` parks on a release token
/// before answering honestly from `written` — the test chooses exactly
/// when each parked occupancy check may complete.
struct ParkingStore {
    state: Arc<ParkingState>,
}

struct ParkingCredential {
    state: Arc<ParkingState>,
    service: String,
    user: String,
}

impl keyring_core::api::CredentialApi for ParkingCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        self.state
            .written
            .lock()
            .expect("map")
            .insert(self.user.clone(), secret.to_vec());
        self.state.sets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        // Announce before parking: a second arrival while a leader waits
        // on a token means a racer entered the check outside the scope
        // lock.
        match self.state.arrived.send(()) {
            Ok(()) | Err(_) => {}
        }
        self.state
            .release
            .lock()
            .expect("gate")
            .recv()
            .expect("release channel open");
        self.state
            .written
            .lock()
            .expect("map")
            .get(&self.user)
            .cloned()
            .ok_or(keyring_core::Error::NoEntry)
    }

    fn delete_credential(&self) -> keyring_core::Result<()> {
        self.state.written.lock().expect("map").remove(&self.user);
        Ok(())
    }

    fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::Credential>>> {
        Err(keyring_core::Error::NoEntry)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl keyring_core::api::CredentialStoreApi for ParkingStore {
    fn vendor(&self) -> String {
        "test-parking".to_string()
    }

    fn id(&self) -> String {
        "parking-store".to_string()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        Ok(keyring_core::Entry::new_with_credential(Arc::new(
            ParkingCredential {
                state: Arc::clone(&self.state),
                service: service.to_string(),
                user: user.to_string(),
            },
        )))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ----- redaction --------------------------------------------------------

/// INV-001: stored secret bytes never appear in Debug/Display surfaces,
/// config export, read values, or the journal — only scoped refs and
/// fingerprints do. A ref is config data; the bytes behind it are not.
#[test]
fn secrets_never_appear_in_config_export_log_output_or_debug() {
    let _store_cases = STORE_CASES.lock().unwrap_or_else(|e| e.into_inner());
    let secret = format!("{SECRET_CANARY}-redaction-material");
    let credential = scoped_ref("redaction-scope");
    let mut journal = AuthJournal::open("redaction");

    // The canary enrolls through the real seam, then a real
    // post-enrollment failure — a second `login` on the occupied scope —
    // renders without the material it now holds. (Store-absent: the
    // scripted and constructed surfaces below still prove the seam's
    // side of the boundary.)
    if let Some(store) = keychain_or_report("redaction", &mut journal) {
        precheck(&store, &[&credential], &mut journal);
        store
            .login(&credential, secret.as_bytes())
            .unwrap_or_else(|e| panic!("canary enrolls: {}", error_variant(&e)));
        let canary = store
            .resolve(&credential)
            .unwrap_or_else(|e| panic!("resolve: {}", error_variant(&e)));
        journal.record(
            "resolve",
            credential.raw(),
            TEST_NAMESPACE,
            &format!("ok sha256:{}", support::sha256_hex(&canary)),
        );
        assert_eq!(
            canary,
            secret.as_bytes(),
            "the canary really is stored material at the scope"
        );
        let failure = store
            .login(&credential, b"clobber-attempt")
            .expect_err("an occupied scope refuses a second enroll");
        for rendered in [format!("{failure}"), format!("{failure:?}")] {
            assert!(
                !rendered.contains(&secret),
                "a real post-enrollment failure carries no material: {rendered}"
            );
        }
        store
            .revoke(&credential)
            .unwrap_or_else(|e| panic!("teardown: {}", error_variant(&e)));
    }

    // SecretRef surfaces carry the ref, never material behind it.
    for rendered in [
        format!("{credential:?}"),
        format!("{credential}"),
        credential.raw().to_string(),
    ] {
        assert!(
            !rendered.contains(&secret),
            "SecretRef surfaces never contain secret material: {rendered}"
        );
        assert!(
            rendered.contains("rivect-test"),
            "the scoped ref is the visible token: {rendered}"
        );
    }

    // Every typed error renders without secret material — errors carry
    // ids, scopes and store classes only.
    let errors = [
        ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "keychain locked".to_string(),
        },
        ProviderError::StoreAmbiguous {
            store: StoreKind::Keychain,
        },
        ProviderError::CredentialUnresolved {
            connection: "primary".to_string(),
            scope: "profiles.default.credential_ref".to_string(),
            cause: None,
        },
        ProviderError::CredentialProfileMismatch {
            connection: "primary".to_string(),
            profile: "default".to_string(),
        },
        ProviderError::CredentialOutsideNamespace {
            store: StoreKind::Keychain,
            scope: credential.scope().to_string(),
        },
        ProviderError::CredentialOccupied {
            scope: credential.scope().to_string(),
        },
        ProviderError::CredentialAbsent {
            scope: credential.scope().to_string(),
        },
    ];
    for err in &errors {
        for rendered in [format!("{err}"), format!("{err:?}")] {
            assert!(
                !rendered.contains(&secret),
                "error surfaces never contain secret material: {rendered}"
            );
        }
    }

    // Config: the scoped ref reads and exports; the secret never enters
    // either surface.
    let toml = "config_version = 1\n\
         [workflow]\nenabled = false\n\
         [connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\n\
         credential_ref = \"keyring:rivect-test/primary\"\nprofile = \"default\"\n\
         [profiles.default]\ncredential_ref = \"keyring:rivect-test/default\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n";
    let mut config = Config::parse_validated(toml).expect("config parses");
    let read_back = config
        .read_value("profiles.default.credential_ref")
        .expect("ref is readable");
    assert_eq!(read_back.as_str(), Some("keyring:rivect-test/default"));
    let edit = config
        .set("workflow.enabled", ConfigValue::Bool(true))
        .expect("edit applies");
    let exported = String::from_utf8(edit.bytes)
        .unwrap_or_else(|e| panic!("export is utf-8: {}", e.utf8_error()));
    assert!(exported.contains("keyring:rivect-test/default"));
    assert!(
        !exported.contains(&secret),
        "config export never contains secret material"
    );

    // Manifest: a request built around the credential's ref renders the
    // ref and never the material — the wire bytes and Debug alike.
    let manifest = RequestManifest {
        attempt_id: "redaction-attempt".to_string(),
        purpose: "main".to_string(),
        world: "redaction-world".to_string(),
        model: ModelAssign::Auto { pool: None },
        effort: EffortAssign::Auto,
        instructions: "redaction fixture instructions".to_string(),
        tools: vec!["read_file".to_string()],
        output_reserve: 1024,
        inputs: format!("goal: fixture\ncredential_ref: {}", credential.raw()),
        inputs_digest: "inputs-digest".to_string(),
        epoch_id: "epoch-1".to_string(),
        mutation_reason: None,
        cost_bound: 1,
    };
    for rendered in [manifest.wire_bytes(), format!("{manifest:?}")] {
        assert!(
            !rendered.contains(&secret),
            "manifest surfaces never contain secret material"
        );
        assert!(
            rendered.contains("keyring:rivect-test/redaction-scope"),
            "the manifest names the scoped ref, not the material"
        );
    }

    // `map_error` trust boundary: `reason` is the platform's own error
    // text verbatim. The seam cannot distinguish material a platform
    // chose to embed, so the contract is that platform text names
    // conditions, never material — this leg pins the passthrough exactly
    // rather than pretending a scrub exists.
    let poisoned = KeyringBackend::new(
        Arc::new(ScriptedStore {
            script: Script::Denied(format!("platform denied: {secret}")),
        }),
        StoreKind::Keychain,
        TEST_NAMESPACE,
    );
    let pinned = keychain_ref("redaction-scope");
    match poisoned.resolve(&pinned) {
        Err(ProviderError::StoreUnavailable { store, reason }) => {
            assert_eq!(store, StoreKind::Keychain);
            assert_eq!(
                reason,
                format!("Couldn't access platform storage: platform denied: {secret}"),
                "the reason is the platform's own text verbatim — the seam adds nothing"
            );
        }
        other => panic!("expected StoreUnavailable, got {}", outcome_variant(&other)),
    }

    // Journal: rows record scoped refs + fingerprints; the secret itself
    // is absent even where a row carries its fingerprint. (Op named
    // "fingerprint", not "login" — when the store is absent no login ran.)
    journal.record(
        "fingerprint",
        credential.raw(),
        TEST_NAMESPACE,
        &format!("ok sha256:{}", support::sha256_hex(secret.as_bytes())),
    );
    drop(journal);
    let journal_on_disk = journal_text();
    assert!(journal_on_disk.contains(&support::sha256_hex(secret.as_bytes())));
    assert!(
        !journal_on_disk.contains(&secret),
        "journal rows carry fingerprints, never secret bytes"
    );
}

// ----- DEC-013 resolution -----------------------------------------------

/// `api_key` connections require `credential_ref` at ingress, so the
/// unresolved legs ride `local` connections (which forbid a ref but admit
/// `profile`); `profiled` carries both bindings so the precedence order —
/// profile ref before connection ref — is the discriminated observation.
fn dec013_config() -> String {
    "config_version = 1\n\
     [workflow]\nenabled = false\n\
     [connections.direct]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/direct\"\n\
     [connections.profiled]\nkind = \"api_key\"\nendpoint = \"https://api2.example.invalid/v1\"\ncredential_ref = \"keyring:rivect/connection-scope\"\nprofile = \"p1\"\n\
     [connections.bare]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:1\"\n\
     [connections.emptyprof]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:3\"\nprofile = \"empty\"\n\
     [profiles.p1]\ncredential_ref = \"keyring:rivect/p1\"\n\
     [profiles.empty]\n\
     [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n"
        .to_string()
}

/// DEC-013 precedence: `connections.<id>.profile` binds the named profile's
/// ref; without a profile binding the connection's own `credential_ref`
/// applies; every failure is a typed denial — never a plaintext path.
#[test]
fn credential_resolution_follows_profile_then_connection_precedence() {
    let config = Config::parse_validated(&dec013_config()).expect("config parses");

    // 1. connections.<id>.profile → profiles.<name>.credential_ref — the
    // profile ref wins over the connection's own credential_ref.
    let resolved = resolve_credential(&config, "profiled")
        .unwrap_or_else(|e| panic!("profile-bound ref resolves: {}", error_variant(&e)));
    assert_eq!(resolved.scope(), "rivect/p1");
    assert_eq!(resolved.store(), NATIVE_KIND);

    // 2. no profile → connections.<id>.credential_ref
    let resolved = resolve_credential(&config, "direct")
        .unwrap_or_else(|e| panic!("connection ref resolves: {}", error_variant(&e)));
    assert_eq!(resolved.scope(), "rivect/direct");

    // Ambiguous/missing resolution is a typed denial.
    assert!(
        matches!(
            resolve_credential(&config, "bare"),
            Err(ProviderError::CredentialUnresolved { .. })
        ),
        "a connection with neither binding is CredentialUnresolved"
    );
    assert!(
        matches!(
            resolve_credential(&config, "emptyprof"),
            Err(ProviderError::CredentialUnresolved { .. })
        ),
        "a profile with no credential_ref is CredentialUnresolved"
    );
    let err = resolve_credential(&config, "undeclared")
        .expect_err("an undeclared connection is denied typed");
    assert!(
        matches!(
            &err,
            ProviderError::UnknownConnection { connection } if connection == "undeclared"
        ),
        "an undeclared connection stays UnknownConnection naming the id: {err}"
    );
    assert!(
        err.to_string().contains("undeclared"),
        "the denial renders the missing id: {err}"
    );

    // A profile-bound ref whose trailing scope segment disagrees with the
    // profile name is a named mismatch — scope and binding cannot diverge.
    let mismatched_toml =
        dec013_config().replace("keyring:rivect/p1", "keyring:rivect/other-scope");
    let mismatched = Config::parse_validated(&mismatched_toml).expect("config parses");
    assert!(
        matches!(
            resolve_credential(&mismatched, "profiled"),
            Err(ProviderError::CredentialProfileMismatch { .. })
        ),
        "profile/scope disagreement is CredentialProfileMismatch"
    );
}

/// SecretRef shape discipline: only `store:scope` tokens parse, `keyring`
/// resolves to the platform's native class, and every segment is validated
/// on the trust boundary even though config ingress already checked.
#[test]
fn secret_ref_parses_only_scoped_store_tokens() {
    let keyring = SecretRef::parse("keyring:rivect/work").expect("keyring parses");
    assert_eq!(keyring.store(), NATIVE_KIND); // the platform's native class
    assert_eq!(keyring.service(), "rivect");
    assert_eq!(keyring.profile(), "work");
    assert_eq!(keyring.scope(), "rivect/work");
    assert_eq!(keyring.raw(), "keyring:rivect/work");

    let pinned = SecretRef::parse("keychain:rivect/work").expect("keychain parses");
    assert_eq!(pinned.store(), StoreKind::Keychain);
    let service = SecretRef::parse("secret-service:rivect/work").expect("secret-service parses");
    assert_eq!(service.store(), StoreKind::SecretService);

    for bad in [
        "not-a-ref",
        "keyring:",
        ":scope",
        "keyring:has space",
        "keyring:double//slash",
        "keyring:/leading",
        "keyring:trailing/",
        "plaintext:rivect/work",
        "file:rivect/work",
        "env:OPENAI_API_KEY",
    ] {
        assert!(
            SecretRef::parse(bad).is_err(),
            "non-scoped or unsupported store ref is rejected: {bad}"
        );
    }
    assert!(
        matches!(
            SecretRef::parse("vault:rivect/work"),
            Err(SecretRefError::UnsupportedStore { .. })
        ),
        "an unknown store label is a named error"
    );
}

/// INV-006 in two layers: `credential_ref` rejects non-scoped shapes at
/// config ingress, and a well-formed ref naming a store this build does
/// not serve — `env:`, `file:`, `vault:` — is refused by the same
/// grammar at the same boundary. No path turns either into plaintext
/// credential material.
#[test]
fn config_rejects_inline_and_secret_looking_credential_values() {
    for value in [SECRET_CANARY, "plaintext", "keyring:has whitespace"] {
        let toml = dec013_config().replace("keyring:rivect/direct", value);
        assert!(
            Config::parse_validated(&toml).is_err(),
            "inline or non-scoped credential_ref is rejected at ingress: {value}"
        );
    }
    for value in ["env:OPENAI_API_KEY", "vault:corp/key", "file:tmp/secret"] {
        let toml = dec013_config().replace("keyring:rivect/direct", value);
        let Err(error) = Config::parse_validated(&toml) else {
            panic!("an unsupported store label is refused at ingress: {value}")
        };
        assert!(
            matches!(
                &error.issue,
                ConfigIssue::UnsupportedCredentialStore { store }
                    if store.as_str() == value.split(':').next().expect("store label")
            ),
            "the typed refusal names the refused store class: {error}"
        );
        assert!(
            !error.to_string().contains(value),
            "the refusal never echoes the credential value: {error}"
        );
    }
}
