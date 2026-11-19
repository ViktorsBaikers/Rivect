//! Settings Center uses only the public config carriers and the machine admission rules.

use super::{Ingress, Refusal, Runtime, Value, call, json};
use rivect::config::{DECISIONS_MODE_KEY, WORKFLOW_KEY};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scope {
    User,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request<'a> {
    Inspect,
    Get {
        key: &'a str,
    },
    Set {
        key: &'a str,
        scope: Scope,
        expected_source_digest: &'a str,
        value: Value,
    },
    Reset {
        key: &'a str,
        scope: Scope,
        expected_source_digest: &'a str,
    },
}

fn execute(
    rt: &mut Runtime,
    session: &str,
    kind: &str,
    mut fields: Value,
) -> Result<Value, Refusal> {
    fields["schema_version"] = json!(1);
    fields["session_id"] = json!(session);
    fields["command"] = json!({"kind":kind});
    call(rt, Ingress::Machine, "command.execute", fields)
}

fn write(
    rt: &mut Runtime,
    session: &str,
    key: &str,
    digest: &str,
    value: Option<Value>,
) -> Result<(), Refusal> {
    if !rivect::config::is_readable_key(key)
        || digest.len() != 64
        || !digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Refusal::Invalid);
    }
    if rt.effective().parsed.is_none() {
        return Err(Refusal::Core(rivect::contracts::ErrorCode::NotFound));
    }
    let mut fields = json!({"expected_source_digest":digest});
    let kind = match (key, value) {
        (DECISIONS_MODE_KEY, Some(value)) => {
            if !matches!(value.as_str(), Some("ask" | "auto" | "inherit")) {
                return Err(Refusal::Invalid);
            }
            fields["op"] = value;
            fields["command_id"] = json!(rivect::contracts::CommandId::generate());
            "decisions.control"
        }
        (WORKFLOW_KEY, Some(Value::Bool(enabled))) => {
            fields["op"] = json!(if enabled { "on" } else { "off" });
            "workflow.control"
        }
        (_, value) => {
            fields["key"] = json!(key);
            if let Some(value) = value {
                fields["value"] = value;
                "config.set"
            } else {
                "config.unset"
            }
        }
    };
    execute(rt, session, kind, fields)?;
    Ok(())
}

fn named_entries(config: &rivect::config::Config, entries: &mut Vec<Value>) -> Result<(), Refusal> {
    for (pattern, sample) in rivect::config::carrier_samples() {
        let Some((prefix, tail)) = pattern.split_once(".<") else {
            continue;
        };
        let Some((_, suffix)) = tail.split_once(">.") else {
            continue;
        };
        let source = entries
            .iter()
            .find(|entry| entry["key"] == sample)
            .ok_or(Refusal::Unknown)?["source"]
            .clone();
        let mut add = |name: &str| {
            let key = if name.contains('.') {
                format!("{prefix}.\"{name}\".{suffix}")
            } else {
                format!("{prefix}.{name}.{suffix}")
            };
            if key != sample
                && let Some(value) = config.read_value(&key)
            {
                entries.push(
                    json!({"key":key,"effective":{"kind":"visible","value":value},"source":source}),
                );
            }
        };
        match prefix {
            "connections" => config.connections.keys().for_each(|name| add(name)),
            "profiles" => config.profiles.keys().for_each(|name| add(name)),
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn page(
    rt: &mut Runtime,
    session: &str,
    request: Request<'_>,
) -> Result<Value, Refusal> {
    let key = match request {
        Request::Inspect => None,
        Request::Get { key } => Some(key),
        Request::Set {
            key,
            scope: Scope::User,
            expected_source_digest,
            value,
        } => {
            write(rt, session, key, expected_source_digest, Some(value))?;
            Some(key)
        }
        Request::Reset {
            key,
            scope: Scope::User,
            expected_source_digest,
        } => {
            write(rt, session, key, expected_source_digest, None)?;
            Some(key)
        }
    };
    let mut list = execute(rt, session, "config.list", json!({}))?;
    let digest = list["source_digest"].take();
    if !digest.is_string() {
        return Err(Refusal::Unknown);
    }
    let entries = list["entries"].as_array_mut().ok_or(Refusal::Unknown)?;
    if let Some(config) = &rt.effective().parsed {
        named_entries(config, entries)?;
    }
    if let Some(key) = key
        && !entries.iter().any(|entry| entry["key"] == key)
    {
        let mut detail = execute(rt, session, "config.get", json!({"key":key}))?;
        entries.push(detail["entry"].take());
    }
    let mut harness = execute(rt, session, "harness.control", json!({"op":"status"}))?;
    Ok(
        json!({"source_digest":digest, "user_config":rt.effective().parsed.is_some(), "decision_mode":rt.effective().decisions_mode().as_str(), "entries":std::mem::take(entries), "harness":{
        "scheduler":harness["scheduler"].take(), "index":harness["index"].take()}, "key_hint":rivect::config::read_key_hint()}),
    )
}
