use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

const CATALOG: &str = "src/providers/models-v1.tsv";

struct Row<'a> {
    key: &'a str,
    wire: &'a str,
    dialect: &'static str,
}

fn parse_row(line: &str) -> Result<(&str, Row<'_>), &'static str> {
    let mut fields = line.split('\t');
    let provider = fields.next().unwrap_or_default();
    let key = fields.next().ok_or("missing model key")?;
    let api = fields.next();
    let wire = fields.next();
    let family = matches!(provider, "opencode-go" | "opencode-zen");
    let valid_id = |id: &str| {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._/:".contains(&b))
    };
    let id = if family {
        key.strip_suffix('*').unwrap_or(key)
    } else {
        key
    };
    if !valid_id(id) || wire.is_some_and(|w| !valid_id(w)) || fields.next().is_some() {
        return Err("invalid model row");
    }
    let routed = match provider {
        "openai" | "openai-codex" | "bedrock-mantle" | "meta" | "abliteration" => false,
        "gitlab-duo" | "github-copilot" | "opencode-go" | "opencode-zen" => true,
        _ => return Err("unknown provider"),
    };
    if api.is_some() != routed || wire.is_some() != (provider == "gitlab-duo") {
        return Err("unexpected model row fields");
    }
    let dialect = match api {
        None | Some("responses") => "Responses",
        Some("chat-completions") => "ChatCompletions",
        Some("messages") => "Messages",
        Some("gemini") if provider == "opencode-zen" => "Gemini",
        _ => return Err("unknown dialect for provider"),
    };
    Ok((
        provider,
        Row {
            key,
            wire: wire.unwrap_or(key),
            dialect,
        },
    ))
}

fn emit_seeds<'a>(
    out: &mut Vec<u8>,
    name: &str,
    ids: impl Iterator<Item = &'a str>,
) -> io::Result<()> {
    writeln!(out, "pub(super) const {name}: &[&str] = &[")?;
    for id in ids {
        writeln!(out, "{id:?},")?;
    }
    writeln!(out, "];")
}

fn emit_models(out: &mut Vec<u8>, provider: &str, mut rows: Vec<Row<'_>>) -> io::Result<()> {
    let name = provider.replace('-', "_");
    let table = name.to_ascii_uppercase();
    match provider {
        "gitlab-duo" => {
            let mut upstream_ids = BTreeSet::new();
            emit_seeds(
                out,
                "GITLAB_RESPONSES",
                rows.iter()
                    .filter(|r| r.dialect == "Responses" && upstream_ids.insert(r.wire))
                    .map(|r| r.wire),
            )?;
            writeln!(
                out,
                "pub(super) const {table}: &[(&str, &str, Dialect)] = &["
            )?;
            for row in rows {
                writeln!(
                    out,
                    "({:?}, {:?}, Dialect::{}),",
                    row.key, row.wire, row.dialect
                )?;
            }
            writeln!(out, "];")
        }
        "github-copilot" => {
            writeln!(out, "pub(super) const {table}: &[(&str, Dialect)] = &[")?;
            for row in rows {
                writeln!(out, "({:?}, Dialect::{}),", row.key, row.dialect)?;
            }
            writeln!(out, "];")
        }
        "opencode-go" | "opencode-zen" => {
            // Exact overrides precede families; longer literal prefixes are more specific.
            rows.sort_unstable_by_key(|r| (r.key.ends_with('*'), std::cmp::Reverse(r.key.len())));
            writeln!(
                out,
                "pub(super) fn {name}(model: &str) -> Dialect {{ match model {{"
            )?;
            for row in rows {
                if let Some(prefix) = row.key.strip_suffix('*') {
                    writeln!(
                        out,
                        "m if m.starts_with({prefix:?}) => Dialect::{},",
                        row.dialect
                    )?;
                } else {
                    writeln!(out, "{:?} => Dialect::{},", row.key, row.dialect)?;
                }
            }
            writeln!(out, "_ => Dialect::ChatCompletions, }} }}")
        }
        _ => emit_seeds(out, &table, rows.iter().map(|r| r.key)),
    }
}

fn catalog(source: &str) -> io::Result<Vec<u8>> {
    let mut groups: BTreeMap<&str, Vec<Row<'_>>> = BTreeMap::new();
    let mut keys = BTreeSet::new();
    let mut targets = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let invalid = |reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{CATALOG}:{}: {reason}", index + 1),
            )
        };
        let (provider, row) = parse_row(line).map_err(invalid)?;
        if !keys.insert((provider, row.key)) {
            return Err(invalid("duplicate model key"));
        }
        if provider == "gitlab-duo"
            && (keys.contains(&(provider, row.wire))
                || targets.contains_key(&row.key)
                || targets
                    .insert(row.wire, row.dialect)
                    .is_some_and(|old| old != row.dialect))
        {
            return Err(invalid("conflicting alias target"));
        }
        groups.entry(provider).or_default().push(row);
    }
    let mut out = Vec::new();
    for (provider, rows) in groups {
        emit_models(&mut out, provider, rows)?;
    }
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    writeln!(io::stdout().lock(), "cargo::rerun-if-changed={CATALOG}")?;
    let dest = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing Cargo output directory")?);
    fs::write(
        dest.join("model_catalog.rs"),
        catalog(&fs::read_to_string(CATALOG)?)?,
    )?;
    Ok(())
}
