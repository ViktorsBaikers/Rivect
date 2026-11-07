//! The registered-but-unserved wire classes (AC-004/DEC-007): the
//! literal `cursor` and `devin` ids record their dialect so a control
//! request denies typed through the Broker's send gate — naming the
//! recorded class and the absent adapter — with zero requests and no
//! accounting. `gitlab-duo-agent` is served by its DWS adapter, so its
//! recorded wire is asserted in `provider_gitlab` instead.
//!
//! The externally blocked `muse-code` id (AC-009) denies on its recorded
//! class before any adapter's dialect claim and before the ledger
//! reserves the send: the candidate walk and the manual pick prove the
//! same class, zero requests, zero accounting and no dialect arm.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test code keeps expect/panic conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, Connection};
use rivect::model::{Broker, ModelError, NullLedger, RejectionCause, RequestManifest};
use rivect::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, SecretRef, StoreKind,
    dialect_for, muse_login,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

mod support;

use support::{CountingLedger, CountingProvider};

/// The scoped reference the fixture `cursor` connection binds: the
/// offline gate resolves the reference shape, never a store lookup.
const CREDENTIAL_REF: &str = "keyring:rivect-test/cursor";
const WORLD: &str = "/world/cursor";
const MODEL: &str = "cursor-agent-model";

/// The fixture `devin` connection's own scoped material, world and pin.
const DEVIN_CREDENTIAL_REF: &str = "keyring:rivect-test/devin";
const DEVIN_WORLD: &str = "/world/devin";
const DEVIN_MODEL: &str = "devin-agent-model";

/// One configured `connection`: `api_key` with scoped material
/// (DEC-011), so the fixed pin is offline-eligible and reaches the send
/// gate these tests prove.
fn unserved_config(connection: &str, credential_ref: &str, model: &str) -> Config {
    Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{connection}]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"{credential_ref}\"\n\
         [models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n\
         [models.purposes.main]\n\
         model = {{ mode = \"fixed\", connection = \"{connection}\", model_id = \"{model}\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the scoped declaration validates")
}

/// Dispatches one prepared pin through the Broker and returns the
/// denial with the caller-held send counter and the Broker itself.
fn unserved_denial(
    connection: &str,
    credential_ref: &str,
    world: &str,
    model: &str,
) -> (ModelError, Arc<AtomicU64>, Broker) {
    let config = unserved_config(connection, credential_ref, model);
    let (provider, requests, _last_manifest) = CountingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, world, &format!("goal: {connection} send"))
        .expect("the scoped material makes the pin offline-eligible");
    let error = broker
        .dispatch(&mut NullLedger, world, &manifest)
        .expect_err("the unserved dialect denies before any adapter leg");
    (error, requests, broker)
}

#[test]
fn cursor_send_denies_unserved_with_zero_requests() {
    let (error, requests, broker) = unserved_denial("cursor", CREDENTIAL_REF, WORLD, MODEL);
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::DialectUnserved { connection, dialect })
                if connection == "cursor" && *dialect == Dialect::CursorAgent
        ),
        "the send gate names the recorded class: {error}"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "no adapter leg ran: a silent peer or base is never contacted"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
}

#[test]
fn devin_send_denies_unserved_with_zero_requests() {
    let (error, requests, broker) =
        unserved_denial("devin", DEVIN_CREDENTIAL_REF, DEVIN_WORLD, DEVIN_MODEL);
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::DialectUnserved { connection, dialect }
                if connection == "devin" && *dialect == Dialect::DevinAgent
        ),
        "the send gate names the recorded class: {source}"
    );
    assert_eq!(
        source.to_string(),
        "connection devin is reserved for dialect devin-agent; no installed adapter serves it in this build",
        "the display names the recorded dialect and the absent adapter"
    );
    assert_eq!(dialect_for("devin"), Some(Dialect::DevinAgent));
    assert_eq!(Dialect::DevinAgent.to_string(), "devin-agent");
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "no adapter leg ran: a silent peer or base is never contacted"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
}

#[test]
fn unserved_denial_names_the_recorded_transport() {
    assert_eq!(dialect_for("cursor"), Some(Dialect::CursorAgent));
    assert_eq!(Dialect::CursorAgent.to_string(), "cursor-agent");
    let error = unserved_denial("cursor", CREDENTIAL_REF, WORLD, MODEL).0;
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert_eq!(
        source.to_string(),
        "connection cursor is reserved for dialect cursor-agent; no installed adapter serves it in this build",
        "the display names the recorded dialect and the absent adapter"
    );
}

/// The fixture `muse-code` connection: an `api_key` declaration with
/// scoped material is offline-eligible, so the fixed pin reaches the
/// recorded external block instead of a live-grant denial.
const MUSE_CREDENTIAL_REF: &str = "keyring:rivect-test/muse-code";
const MUSE_WORLD: &str = "/world/muse-code";
const MUSE_MODEL: &str = "muse-spark-1.3";

/// The credential-store seam the denial must never reach: every call is
/// counted and the write legs (a mint) counted apart, so "mints no key" is
/// an observed zero rather than an inference from the no-send counter.
#[derive(Debug, Default)]
struct StoreProbe {
    calls: AtomicU64,
    mints: AtomicU64,
}

impl StoreProbe {
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn mints(&self) -> u64 {
        self.mints.load(Ordering::SeqCst)
    }
}

impl CredentialStore for StoreProbe {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn occupied(&self, _credential: &SecretRef) -> Result<bool, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(false)
    }

    fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }

    fn login(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.mints.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ProviderError::CredentialAbsent {
            scope: credential.scope().to_string(),
        })
    }

    fn refresh(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.mints.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn revoke(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn logout(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A foreign adapter claiming every connection outside the build's reserved
/// dialect roster — `muse-code` included. If the recorded external block did
/// not precede the `serves` claim, this double would mint the credential and
/// receive the request, so its counters prove the denial's order.
struct ServesEverythingProvider {
    requests: Arc<AtomicU64>,
    store: Arc<StoreProbe>,
}

impl ServesEverythingProvider {
    fn new() -> (Self, Arc<AtomicU64>, Arc<StoreProbe>) {
        let requests = Arc::new(AtomicU64::new(0));
        let store = Arc::new(StoreProbe::default());
        (
            Self {
                requests: Arc::clone(&requests),
                store: Arc::clone(&store),
            },
            requests,
            store,
        )
    }
}

impl Provider for ServesEverythingProvider {
    fn name(&self) -> &'static str {
        "serves-everything"
    }

    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        dialect_for(connection).is_none()
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        // A served adapter's credential leg mints before the wire: the
        // probe's zero is the "mints no key" observable.
        let credential = SecretRef::parse(MUSE_CREDENTIAL_REF).expect("the fixture ref is scoped");
        self.store
            .login(&credential, b"probe-mint")
            .expect("the probe store accepts a mint");
        panic!("the externally blocked connection never receives a request");
    }
}

/// A claiming adapter that refuses every request definitively: the served
/// chain candidate that cannot answer, so the walk exhausts and its
/// rejection list is observable.
struct RefusingProvider;

impl Provider for RefusingProvider {
    fn name(&self) -> &'static str {
        "refusing"
    }

    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        dialect_for(connection).is_none()
    }

    fn send(&mut self, _manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Err(ProviderError::UnsendableRequest {
            connection: "reserve".to_string(),
            reason: "the fixture adapter declines every request".to_string(),
        })
    }
}

/// AC-009: a configured `muse-code` pin denies typed with the recorded
/// external class — zero requests, zero accounting and no dialect arm —
/// and no adapter's `serves` claim can change the outcome.
#[test]
fn muse_wire_denied() {
    let config = unserved_config("muse-code", MUSE_CREDENTIAL_REF, MUSE_MODEL);
    let (provider, requests, store) = ServesEverythingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, MUSE_WORLD, "goal: muse send")
        .expect("the scoped material makes the pin offline-eligible");
    let mut ledger = CountingLedger::new();
    let error = broker
        .dispatch(&mut ledger, MUSE_WORLD, &manifest)
        .expect_err("the recorded external block denies before any adapter leg");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::ExternalBlocked { connection, class }
                if connection == "muse-code" && *class == muse_login::EXTERNAL_CLASS
        ),
        "the send gate names the recorded external class: {source}"
    );
    assert_eq!(
        muse_login::EXTERNAL_CLASS,
        "BLOCKED_EXTERNAL",
        "the class is the producer's recorded constant, never a second literal"
    );
    assert_eq!(
        source.to_string(),
        "connection muse-code is externally blocked (BLOCKED_EXTERNAL)",
        "the display is lowercase and names the class"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "a foreign adapter's claim cannot turn the denial into a request"
    );
    assert_eq!(
        ledger.begun, 0,
        "the denial lands before the ledger reserves the send"
    );
    assert_eq!(ledger.finished, 0, "no reservation is opened to close");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
    assert!(
        broker.accounting_record(&manifest.attempt_id).is_none(),
        "a denied send mints no accounting row"
    );
    assert_eq!(store.mints(), 0, "the denial mints no credential");
    assert_eq!(store.calls(), 0, "no credential leg ran for the denied pin");
    assert_eq!(
        dialect_for("muse-code"),
        None,
        "the blocked id stays outside the dialect roster"
    );
}

/// AC-009: the auto walk's candidate re-check names the recorded external
/// class for a `muse-code` chain entry, before the dialect claim and the
/// ledger bracket, so the entry never receives the request.
#[test]
fn muse_candidate_rejection_names_the_external_block() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.cursor]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"keyring:rivect-test/cursor\"\n\
         [connections.muse-code]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"keyring:rivect-test/muse-code\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n\
         [models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"cursor\", model_id = \"cursor-agent-model\" }\n\
         fallback = { mode = \"auto\", chain = [{ mode = \"fixed\", connection = \"muse-code\", model_id = \"muse-spark-1.3\" }] }\n",
    )
    .expect("the cursor pin and the Muse chain entry validate");
    let (provider, requests, store) = ServesEverythingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, MUSE_WORLD, "goal: muse candidate")
        .expect("the cursor pin prepares");
    let error = broker
        .dispatch(&mut NullLedger, MUSE_WORLD, &manifest)
        .expect_err("the unserved primary walks its chain");
    let ModelError::FallbackExhausted {
        rejected,
        attempted,
        ..
    } = error
    else {
        panic!("the blocked chain entry exhausts the walk: {error:?}");
    };
    assert!(
        attempted.is_empty(),
        "the blocked entry never receives a send: {attempted:?}"
    );
    let muse = rejected
        .iter()
        .find(|rejection| rejection.connection == "muse-code")
        .expect("the Muse chain entry keeps its typed cause");
    assert!(
        matches!(
            &muse.cause,
            RejectionCause::ExternalBlocked { class } if *class == muse_login::EXTERNAL_CLASS
        ),
        "the candidate re-check names the recorded external class: {:?}",
        muse.cause
    );
    assert_eq!(
        muse.cause.to_string(),
        "externally blocked (BLOCKED_EXTERNAL)",
        "the display is lowercase and names the class"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "no adapter leg ran for the blocked entry"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a rejected candidate is never accounted"
    );
    assert_eq!(
        store.mints(),
        0,
        "the rejected candidate mints no credential"
    );
    assert_eq!(
        store.calls(),
        0,
        "no credential leg ran for the blocked entry"
    );
}

/// AC-009: a manual pick of `muse-code` denies on the recorded external
/// class before the offer set and the ledger bracket — the pause never
/// offers it, and a direct pick still meets the typed denial.
#[test]
fn muse_manual_fallback_denies_before_begin_send() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.cursor]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"keyring:rivect-test/cursor\"\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
         [connections.muse-code]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"keyring:rivect-test/muse-code\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n\
         [models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"cursor\", model_id = \"cursor-agent-model\" }\n\
         fallback = { mode = \"manual\" }\n",
    )
    .expect("the servable reserve and the Muse declaration validate");
    let (provider, requests, store) = ServesEverythingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, MUSE_WORLD, "goal: muse manual")
        .expect("the cursor pin prepares");
    let mut ledger = CountingLedger::new();
    let paused = broker
        .dispatch(&mut ledger, MUSE_WORLD, &manifest)
        .expect_err("the definitive primary denial pauses");
    assert!(
        matches!(paused, ModelError::ManualFallbackPending { .. }),
        "a servable different connection still pauses: {paused:?}"
    );
    assert_eq!(
        ledger.begun, 0,
        "the paused dispatch denies before the ledger reserves a send"
    );
    let choice = broker
        .pending_choice(&manifest.attempt_id)
        .expect("the pause serves its candidates");
    assert_eq!(
        choice.candidates,
        vec!["reserve".to_string()],
        "the blocked connection is never offered, not even to an adapter that claims it: {choice:?}"
    );
    let picked =
        broker.dispatch_fallback_choice(&mut ledger, MUSE_WORLD, &manifest.attempt_id, "muse-code");
    let Err(ModelError::ManualChoiceRejected {
        connection, cause, ..
    }) = picked
    else {
        panic!("the blocked pick is refused before the send: {picked:?}");
    };
    assert_eq!(connection, "muse-code");
    assert!(
        matches!(
            &cause,
            RejectionCause::ExternalBlocked { class } if *class == muse_login::EXTERNAL_CLASS
        ),
        "the manual path names the recorded external class: {cause:?}"
    );
    assert_eq!(
        cause.to_string(),
        "externally blocked (BLOCKED_EXTERNAL)",
        "the display is lowercase and names the class"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "the blocked pick never reaches an adapter"
    );
    assert_eq!(ledger.begun, 0, "the refused pick never reserves a send");
    assert_eq!(ledger.finished, 0, "and closes no reservation either");
    assert_eq!(
        broker.accounted_requests(),
        0,
        "the manual denial lands before the ledger reserves the send"
    );
    assert_eq!(store.mints(), 0, "the refused pick mints no credential");
    assert_eq!(
        store.calls(),
        0,
        "no credential leg ran for the refused pick"
    );
}

/// AC-009: an adapter that declines the id — every shipped adapter's answer
/// for a dialect it does not speak — still meets the recorded external block,
/// never the dialect claim, so the class names the block rather than the
/// adapter's own refusal.
#[test]
fn muse_declining_adapter_denies_external_block_not_dialect_mismatch() {
    let config = unserved_config("muse-code", MUSE_CREDENTIAL_REF, MUSE_MODEL);
    let (provider, requests, _last_manifest) = CountingProvider::new();
    assert!(
        !provider.serves(
            "muse-code",
            config
                .connections
                .get("muse-code")
                .expect("the fixture declares the blocked id")
        ),
        "the shipped double declines the id, so the class is the discriminator"
    );
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, MUSE_WORLD, "goal: muse declined")
        .expect("the scoped material makes the pin offline-eligible");
    let mut ledger = CountingLedger::new();
    let error = broker
        .dispatch(&mut ledger, MUSE_WORLD, &manifest)
        .expect_err("the recorded external block denies before the dialect claim");
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::ExternalBlocked { connection, class }
                if connection == "muse-code" && *class == muse_login::EXTERNAL_CLASS
        ),
        "a declining adapter still meets the block, never DialectMismatch: {source}"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "the declining adapter receives no request"
    );
    assert_eq!(
        ledger.begun, 0,
        "the denial lands before the ledger reserves the send"
    );
}

/// AC-009: a blocked primary is a definitive denial, so an `auto` chain still
/// walks — the served candidate is attempted and the blocked id lands in the
/// walk's rejections as `ExternalBlocked`, never as an unknown outcome that
/// would end the walk before any entry is consulted.
#[test]
fn muse_blocked_primary_walks_the_auto_chain() {
    let config = Config::parse_validated(
        "config_version = 1\n\
         [connections.reserve]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11435\"\n\
         [connections.muse-code]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"keyring:rivect-test/muse-code\"\n\
         [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n\
         [models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"muse-code\", model_id = \"muse-spark-1.3\" }\n\
         fallback = { mode = \"auto\", chain = [\n\
         { mode = \"fixed\", connection = \"muse-code\", model_id = \"muse-spark-1.3\" },\n\
         { mode = \"fixed\", connection = \"reserve\", model_id = \"reserve-model\" },\n\
         ] }\n",
    )
    .expect("the blocked pin and its walkable chain validate");
    let mut broker = Broker::new(Box::new(RefusingProvider));
    let manifest = broker
        .prepare("main", &config, MUSE_WORLD, "goal: muse auto")
        .expect("the blocked pin prepares; the denial belongs to the send");
    let mut ledger = CountingLedger::new();
    let error = broker
        .dispatch(&mut ledger, MUSE_WORLD, &manifest)
        .expect_err("the chain exhausts after the served candidate refuses");
    let ModelError::FallbackExhausted {
        rejected,
        attempted,
        source,
        ..
    } = error
    else {
        panic!("the blocked primary is definitive, so the walk ran: {error:?}");
    };
    assert!(
        matches!(&*source, ProviderError::ExternalBlocked { .. }),
        "the walk's source keeps the recorded block: {source}"
    );
    assert_eq!(
        attempted,
        vec!["reserve".to_string()],
        "the served candidate was attempted instead of stopping the walk"
    );
    assert_eq!(
        ledger.begun, 1,
        "the served candidate's send is the one entered reservation"
    );
    let muse = rejected
        .iter()
        .find(|rejection| rejection.connection == "muse-code")
        .expect("the blocked chain entry keeps its typed cause");
    assert!(
        matches!(
            &muse.cause,
            RejectionCause::ExternalBlocked { class } if *class == muse_login::EXTERNAL_CLASS
        ),
        "the blocked entry is never an unknown outcome: {:?}",
        muse.cause
    );
}
