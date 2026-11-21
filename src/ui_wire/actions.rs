//! Narrow operator projections; all effects use the existing command dispatcher.

use super::{Refusal, dispatch_common, string};
use rivect::commands::{EconomySnapshot, Ingress, Runtime};
use rivect::contracts::{Availability, ErrorCode, SessionId, TaskId};
use rivect::resources::sanitize_status_cause;
use serde::Deserialize;
use serde_json::{Value, json};

mod settings;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Action<'a> {
    Settings {},
    SettingsCenter {
        #[serde(borrow)]
        request: settings::Request<'a>,
    },
    Permissions {},
    Accounting {},
    Dock {
        task_id: &'a str,
    },
    LoginBrowser {},
    LoginDevice {},
    LoginProviders {},
    LoginConnect {
        provider: &'a str,
    },
    LoginStart {
        provider: &'a str,
        method: &'a str,
    },
    LoginKey {
        provider: &'a str,
        key: &'a str,
    },
    LoginComplete {},
    LoginCallback {
        redirect: &'a str,
    },
    LoginCancel {},
}

fn call(rt: &mut Runtime, ingress: Ingress, method: &str, params: Value) -> Result<Value, Refusal> {
    let request = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    dispatch_common(rt, ingress, &serde_json::to_string(&request)?)
}

fn command(rt: &mut Runtime, session: &str, kind: &str) -> Result<Value, Refusal> {
    call(
        rt,
        Ingress::Machine,
        "command.execute",
        json!({"schema_version":1,
        "session_id":session,"command":{"kind":kind}}),
    )
}

fn rendered(value: &Value) -> String {
    match value {
        Value::Null => "unknown".to_owned(),
        Value::String(text) => sanitize_status_cause(text),
        other => other.to_string(),
    }
}

fn settings(rt: &mut Runtime, session: &str) -> Result<Vec<String>, Refusal> {
    let settings = command(rt, session, "settings.open")?;
    let mut lines = vec!["Settings:".to_owned()];
    for entry in settings["entries"].as_array().ok_or(Refusal::Unknown)? {
        let key = string(entry, "key")?;
        let source = string(&entry["source"], "kind")?;
        let value = entry.pointer("/effective/value").ok_or(Refusal::Unknown)?;
        lines.push(format!("{key} = {} ({source})", rendered(value)));
    }
    Ok(lines)
}

fn permissions(rt: &mut Runtime, session: &str) -> Result<Vec<String>, Refusal> {
    let permissions = command(rt, session, "permissions.view")?;
    let mut lines = vec![format!(
        "Permissions: decisions {}",
        string(&permissions, "decisions")?
    )];
    for row in permissions["boundaries"]
        .as_array()
        .ok_or(Refusal::Unknown)?
    {
        lines.push(format!(
            "{}: {}",
            string(row, "boundary")?,
            string(row, "mode")?
        ));
    }
    if let Some(grant) = permissions.get("grant").filter(|g| !g.is_null()) {
        lines.push(format!(
            "grant: {} at {}",
            string(grant, "grant_id")?,
            rendered(&grant["scope_root"])
        ));
    }
    Ok(lines)
}

fn number(value: Option<u64>) -> impl std::fmt::Display {
    std::fmt::from_fn(move |out| match value {
        Some(n) => write!(out, "{n}"),
        None => out.write_str("unknown"),
    })
}

fn accounting(e: &EconomySnapshot, pending_sends: Option<u64>) -> Vec<String> {
    let cache = std::fmt::from_fn(|out| match e.cache_rate {
        Some((read, input)) => write!(out, "{read}/{input}"),
        None => out.write_str("unknown"),
    });
    let label = |value: Option<&str>| sanitize_status_cause(value.unwrap_or("unknown"));
    vec![
        "Accounting:".to_owned(),
        format!(
            "project: {} · cwd: {}",
            sanitize_status_cause(&e.project),
            sanitize_status_cause(&e.cwd)
        ),
        format!(
            "tokens: {} ({})",
            number(e.settled_tokens),
            e.settled_source
        ),
        format!(
            "charged units: {} ({})",
            number(e.charged_units),
            e.cost_source
        ),
        format!("quota: {} ({})", number(e.quota_remaining), e.quota_source),
        format!(
            "reset: {} ({})",
            label(e.reset_at.as_deref()),
            e.reset_source
        ),
        format!(
            "context: {} / {} tokens ({})",
            number(e.context_tokens),
            number(e.context_window),
            e.context_source
        ),
        format!(
            "cache read/input: {cache} ({})",
            sanitize_status_cause(&e.cache_source)
        ),
        format!(
            "agents: {} ({}) · pending sends: {}",
            e.agents,
            e.agents_source,
            number(pending_sends)
        ),
        format!(
            "model: {} ({})",
            label(e.model.as_deref()),
            label(e.source.as_deref())
        ),
        format!(
            "effort: {} ({})",
            label(e.effort.as_deref()),
            e.effort_source
        ),
        format!(
            "purpose: {} · connection: {}",
            label(e.purpose.as_deref()),
            label(e.connection.as_deref())
        ),
    ]
}

fn login(rt: &mut Runtime, action: Action<'_>) -> Result<Value, Refusal> {
    // The picker reads the catalogue without minting anything.
    if let Action::LoginProviders {} = action {
        let result = call(
            rt,
            Ingress::Machine,
            "auth.providers",
            json!({"schema_version":1}),
        )?;
        return Ok(json!({"lines":[], "login":"idle", "providers":result["providers"]}));
    }
    // Selecting a row declares its connection through the journaled config
    // admission before any leg is minted.
    if let Action::LoginConnect { provider } = action {
        let result = call(
            rt,
            Ingress::Machine,
            "provider.connect",
            json!({"schema_version":1,"id":provider}),
        )?;
        let line = if result.get("declared").is_some() {
            format!("{} is already declared.", sanitize_status_cause(provider))
        } else {
            format!("Declared {} for sign-in.", sanitize_status_cause(provider))
        };
        return Ok(json!({"lines":[line], "login":"idle"}));
    }
    // A stored-key row: the connection is declared, then the key is written
    // at its profile scope. Nothing is sent to the provider.
    if let Action::LoginKey { provider, key } = action {
        call(
            rt,
            Ingress::Machine,
            "provider.connect",
            json!({"schema_version":1,"id":provider}),
        )?;
        let result = call(
            rt,
            Ingress::Machine,
            "auth.login.apikey",
            json!({"schema_version":1,"connection":provider,"key":key}),
        )?;
        let profile = sanitize_status_cause(string(&result, "profile")?);
        let (status, error) = rivect::ui::connected_status(&rt.config_for_broker(), &profile);
        let status = sanitize_status_cause(&status);
        let mut lines = vec![format!("Login complete: {profile}"), status.clone()];
        if let Some(error) = error {
            lines.push(format!(
                "Model selection unavailable: {} stage",
                error.stage
            ));
        }
        return Ok(json!({"lines":lines, "login":"connected", "status":status}));
    }
    let start = match &action {
        Action::LoginStart { provider, method } => Some((*provider, *method)),
        Action::LoginBrowser {} => Some(("openai-codex", "browser")),
        Action::LoginDevice {} => Some(("openai-codex", "device")),
        _ => None,
    };
    let (method, params) = if let Some((provider, mode)) = start {
        (
            "auth.login.begin",
            json!({"schema_version":1,"connection":provider,"mode":mode}),
        )
    } else {
        match action {
            Action::LoginCancel {} => ("auth.login.cancel", json!({"schema_version":1})),
            Action::LoginComplete {} => ("auth.login.complete", json!({"schema_version":1})),
            Action::LoginCallback { redirect } => (
                "auth.login.complete",
                json!({"schema_version":1,"redirect":redirect}),
            ),
            _ => return Err(Refusal::Invalid),
        }
    };
    let provider = start
        .map(|(provider, _)| provider)
        .unwrap_or("openai-codex");
    let mode = start.map(|(_, mode)| mode).unwrap_or("browser");
    let result = call(rt, Ingress::Machine, method, params)?;
    match method {
        "auth.login.cancel" => {
            let line = match string(&result, "state")? {
                "none" => "No login is pending.",
                "cancelled" => "Login cancelled.",
                _ => return Err(Refusal::Unknown),
            };
            Ok(json!({"lines":[line], "login":"idle"}))
        }
        "auth.login.begin" => {
            let url = sanitize_status_cause(string(&result, "verification_url")?);
            let code = result["user_code"].as_str().map(sanitize_status_cause);
            let capture = result["capture"].as_bool().unwrap_or(false);
            let mut lines = vec![format!("Login pending: {url}")];
            if let Some(code) = &code {
                lines.push(format!("Enter code: {code}"));
            } else if capture {
                lines.push("Waiting for the browser redirect.".to_owned());
            } else {
                lines.push("Paste the redirect URL when the browser returns here.".to_owned());
            }
            Ok(json!({
                "lines":lines,
                "login":"pending",
                "pending":{
                    "provider":provider,
                    "method":mode,
                    "url":url,
                    "user_code":code,
                    "expires_in":result["expires_in"].clone(),
                    "capture":capture,
                },
            }))
        }
        _ => {
            if let Some(profile) = result["profile"].as_str() {
                let (status, error) =
                    rivect::ui::connected_status(&rt.config_for_broker(), profile);
                let status = sanitize_status_cause(&status);
                let mut lines = vec![
                    format!("Login complete: {}", sanitize_status_cause(profile)),
                    status.clone(),
                ];
                if let Some(error) = error {
                    lines.push(format!(
                        "Model selection unavailable: {} stage",
                        error.stage
                    ));
                }
                Ok(json!({"lines":lines, "login":"connected", "status":status}))
            } else {
                Ok(
                    json!({"lines":[format!("Login pending: {}", sanitize_status_cause(string(&result, "state")?))], "login":"pending"}),
                )
            }
        }
    }
}

fn action(params: &Value) -> Result<Action<'_>, Refusal> {
    if params.as_object().is_none_or(|fields| fields.len() != 3) {
        return Err(Refusal::Invalid);
    }
    Action::deserialize(&params["action"]).map_err(Refusal::ActionInput)
}

fn dock(rt: &mut Runtime, session: &str, subject: &str) -> Result<Value, Refusal> {
    let task = TaskId(subject.to_owned());
    rt.store()
        .task_page_anchor(&SessionId(session.to_owned()), &task)?;
    let status = call(
        rt,
        Ingress::Machine,
        "runtime.status",
        json!({
            "schema_version":1, "session_id":session, "page":{"page_size":rivect::contracts::PAGE_MAX}
        }),
    )?;
    let mut rows = rivect::ui::task_dock(&status);
    let economy = rows.pop().ok_or(Refusal::Unknown)?;
    let profile = if rows.last().is_some_and(|row| row.starts_with("profile:")) {
        rows.pop()
    } else {
        None
    };
    if rows.len() > 3 {
        let hidden = rows.len() - 2;
        let last = rows.pop().ok_or(Refusal::Unknown)?;
        rows.truncate(2);
        rows.push(format!("+{hidden} more · {last}"));
    }
    let rivect::config::ConfigViewValue::Visible {
        value: Value::Bool(silenced),
    } = &rt.effective().context_entry.effective
    else {
        return Err(Refusal::Unknown);
    };
    let percent = if *silenced {
        None
    } else {
        let bytes = rt.store().assembled_context(&task)?.text.len();
        let percent = bytes.saturating_mul(100) / rivect::contracts::MODEL_WIRE_MAX_BYTES;
        (percent >= 80).then_some(percent)
    };
    let economy_state = &status["economy"];
    let model = economy_state["model"].as_str().unwrap_or("unknown");
    let context = number(economy_state["context_tokens"].as_u64());
    let summary = format!("context {context} tok · model {model}");
    Ok(json!({
        "session_id": session, "task_id": subject, "rows": rows, "profile": profile,
        "economy": economy, "summary": summary, "percent": percent,
    }))
}

// Freeze only admitted projections before the worker borrows the single runtime.
pub(super) struct ActiveViews {
    settings: Result<Vec<String>, ErrorCode>,
    center: Result<Value, ErrorCode>,
    permissions: Result<Vec<String>, ErrorCode>,
    economy: EconomySnapshot,
    dock: Result<Value, ErrorCode>,
}

impl ActiveViews {
    pub(super) fn capture(rt: &mut Runtime, session: &str, task: &str) -> Self {
        Self {
            settings: settings(rt, session).map_err(|err| err.code()),
            center: settings::page(rt, session, settings::Request::Inspect)
                .map_err(|err| err.code()),
            permissions: permissions(rt, session).map_err(|err| err.code()),
            economy: rt.economy().clone(),
            dock: dock(rt, session, task).map_err(|err| err.code()),
        }
    }

    pub(super) fn action(&self, params: &Value, pending: Option<bool>) -> Result<Value, Refusal> {
        let lines = match action(params)? {
            Action::SettingsCenter { request } => {
                let key = match request {
                    settings::Request::Inspect => None,
                    settings::Request::Get { key } => Some(key),
                    _ => return Err(Refusal::Core(ErrorCode::Conflict)),
                };
                let page = self.center.as_ref().map_err(|code| Refusal::Core(*code))?;
                if let Some(key) = key
                    && !page["entries"]
                        .as_array()
                        .ok_or(Refusal::Unknown)?
                        .iter()
                        .any(|e| e["key"] == key)
                {
                    return Err(Refusal::Core(ErrorCode::Conflict));
                }
                return Ok(page.clone());
            }
            Action::Dock { task_id } => {
                let view = self.dock.as_ref().map_err(|code| Refusal::Core(*code))?;
                if view["task_id"] != task_id {
                    return Err(Refusal::Core(ErrorCode::Conflict));
                }
                return Ok(view.clone());
            }
            Action::Settings {} => &self.settings,
            Action::Permissions {} => &self.permissions,
            Action::Accounting {} => {
                let count =
                    pending.map(|open| self.economy.pending_sends.saturating_add(u64::from(open)));
                let mut lines = accounting(&self.economy, count);
                lines.push("Settled totals as of task admission.".to_owned());
                return Ok(json!({"lines":lines}));
            }
            _ => return Err(Refusal::Core(ErrorCode::Conflict)),
        };
        Ok(json!({"lines":lines.as_ref().map_err(|code| Refusal::Core(*code))?}))
    }
}

pub(super) fn project(rt: &mut Runtime, params: &Value) -> Result<Value, Refusal> {
    let session = string(params, "session_id")?;
    let lines = match action(params)? {
        Action::Dock { task_id } => return dock(rt, session, task_id),
        Action::SettingsCenter { request } => return settings::page(rt, session, request),
        Action::Settings {} => settings(rt, session)?,
        Action::Permissions {} => permissions(rt, session)?,
        Action::Accounting {} => accounting(rt.economy(), Some(rt.economy().pending_sends)),
        action => return login(rt, action),
    };
    Ok(json!({"lines":lines}))
}

pub(super) fn question(rt: &Runtime, params: &Value, witness: bool) -> Result<Value, Refusal> {
    let session = SessionId(string(params, "session_id")?.to_owned());
    let task = TaskId(string(params, "task_id")?.to_owned());
    rt.store().task_page_anchor(&session, &task)?;
    // The task exists in the bound session; current_question also excludes superseded intent.
    let preview = rt.proposed_diff(&session, &task)?;
    let question = rt.store().current_question(&task)?.map(|(q, _)| {
        // Unlike a status line, consent copy must distinguish a control-bearing
        // path from both its stripped spelling and a path with literal escapes.
        let text = |value: &str| value.escape_debug().to_string();
        let options: Vec<_> = q.options.iter().map(|option| {
            let availability = match &option.availability {
                Availability::Enabled => json!({"kind":"enabled"}),
                Availability::Disabled { reason } => json!({"kind":"disabled","reason":text(reason)}),
            };
            json!({"option_id":option.option_id,"label":text(&option.label),
                "consequences":text(&option.consequences),"availability":availability})
        }).collect();
        let mut prompt = text(&q.prompt);
        if let Some((summary, _)) = preview {
            prompt.push('\n');
            prompt.push_str(summary);
        }
        json!({"question_id":q.question_id,"question_revision":q.question_revision.to_string(),
            "intent_revision":q.intent_revision.to_string(),"custom":q.accepts_custom(),
            "title": if q.is_permission() {"awaiting permission"} else {"awaiting decision"},
            "prompt":prompt,"can_reveal_diff":witness && preview.is_some_and(|(_, available)| available),"options":options,"recommended_option_id":q.recommended_option_id,
            "recommendation_basis":text(&q.recommendation_basis)})
    });
    Ok(json!({"session_id":session,"task_id":task,"question":question}))
}

fn revision(params: &Value, key: &str) -> Result<u64, Refusal> {
    let raw = string(params, key)?;
    if raw.is_empty()
        || (raw.starts_with('0') && raw.len() > 1)
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Refusal::Invalid);
    }
    Ok(raw.parse()?)
}

pub(super) fn reveal(rt: &Runtime, params: &Value) -> Result<Value, Refusal> {
    if params.as_object().is_none_or(|f| f.len() != 6) {
        return Err(Refusal::Invalid);
    }
    let session = SessionId(string(params, "session_id")?.to_owned());
    let task = TaskId(string(params, "task_id")?.to_owned());
    let id = string(params, "question_id")?;
    let intent = revision(params, "expected_intent_revision")?;
    let rev = revision(params, "question_revision")?;
    let diff = rt
        .reveal_proposed_diff(&session, &task, id, rev, intent)?
        .ok_or(Refusal::Denied)?;
    Ok(json!({"diff":diff}))
}

pub(super) fn answer(
    rt: &mut Runtime,
    params: &Value,
    witness: bool,
    launch: &mut Option<super::Work>,
) -> Result<Value, Refusal> {
    if !witness {
        return Err(Refusal::Denied);
    }
    let image = params.get("image");
    if params
        .as_object()
        .is_none_or(|f| f.len() != 7 + usize::from(image.is_some()))
    {
        return Err(Refusal::Invalid);
    }
    if let Some(image) = image
        && (image.as_object().is_none_or(|f| f.len() != 5)
            || string(image, "path")?.is_empty()
            || rivect::model::ImageMedia::parse(string(image, "media_type")?).is_none())
    {
        return Err(Refusal::Invalid);
    }
    let frame = question(rt, params, witness)?;
    let q = &frame["question"];
    let id = string(params, "question_id")?;
    let intent = revision(params, "expected_intent_revision")?;
    let revision = revision(params, "question_revision")?;
    if q["question_id"] != id
        || q["intent_revision"] != params["expected_intent_revision"]
        || q["question_revision"] != params["question_revision"]
    {
        return Err(Refusal::Denied);
    }
    let selection = &params["selection"];
    if selection.as_object().is_none_or(|fields| fields.len() != 2) {
        return Err(Refusal::Invalid);
    }
    let admissible = match string(selection, "kind")? {
        "option" => {
            let selected = string(selection, "option_id")?;
            q["options"].as_array().is_some_and(|options| {
                options.iter().any(|op| {
                    op["option_id"] == selected && op["availability"]["kind"] == "enabled"
                })
            })
        }
        "custom" => {
            q["custom"] == true
                && selection["text"].as_str().is_some_and(|text| {
                    !text.trim().is_empty() && text.len() <= rivect::contracts::TEXT_MAX_BYTES
                })
        }
        _ => false,
    };
    if !admissible {
        return Err(Refusal::Denied);
    }
    let preview = if let Some(claim) = image {
        let preview = super::composer::image(rt, string(claim, "path")?, witness)?;
        if &preview.receipt != claim {
            return Err(Refusal::Denied);
        }
        Some(preview)
    } else {
        None
    };
    if !crate::ui_launch::confirm(&frame, params).map_err(Refusal::Witness)? {
        return Err(Refusal::Denied);
    }
    let mut request = json!({"schema_version":1,"kind":"answer","session_id":frame["session_id"],"task_id":frame["task_id"],
        "command_id":rivect::contracts::CommandId::generate(),"question_id":id,"expected_intent_revision":intent,
        "question_revision":revision,"selection":selection});
    if let Some(preview) = &preview {
        request["image"] =
            json!({"path":preview.pin.location.target, "media_type":preview.receipt["media_type"]});
    }
    let task = TaskId(string(params, "task_id")?.to_owned());
    let session = SessionId(string(params, "session_id")?.to_owned());
    *launch = Some(super::Work::Answer(
        rt.begin_terminal_answer(request, preview.as_ref().map(|p| &p.pin))
            .map_err(Refusal::Core)?,
    ));
    let snapshot = super::committed_snapshot(rt, &session, &task)?;
    Ok(json!({"lines":["decision answer recorded"],"snapshot":snapshot}))
}
