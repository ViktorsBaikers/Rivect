//! Ephemeral terminal projection; these bytes never belong in a question or event row.

use std::path::Path;

const WITHHELD: &str = "Preview withheld: sensitive or unclassified content.";
const TOO_LARGE: &str = "Preview withheld: change exceeds the terminal preview limit.";

fn sensitive(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "authorization",
        "bearer",
        "api_key",
        "apikey",
        "api-key",
        "private key",
        "private_key",
        "access_key",
        "keyring",
        ".env",
        ".ssh",
        "ghp_",
        "github_pat_",
        "akia",
        "sk-",
        "-----begin",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

// An opaque literal, comment or free-form text is not safe merely because it
// misses a credential prefix. Only display short, printable source tokens.
fn source_line(line: &str) -> bool {
    let line = line.strip_suffix('\n').unwrap_or(line);
    line.is_empty()
        || (line.len() <= 240
            && line.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
            && !line.contains(['"', '\'', '`', '\\', '#'])
            && !line.contains("//")
            && line.contains([';', '{', '}', '(', ')', '=', '[', ']'])
            && line
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .all(|token| {
                    token.len() <= 32
                        && !token
                            .as_bytes()
                            .windows(4)
                            .any(|run| run.iter().all(u8::is_ascii_digit))
                }))
}

fn ambiguous(text: &str) -> bool {
    // A changed line inside a multiline string or block comment could itself
    // look like code. Refuse the whole preview when the lexical context is unclear.
    text.contains(['\0', '`', '\\'])
        || text.contains("/*")
        || text.contains("r#")
        || text
            .lines()
            .any(|line| line.bytes().filter(|b| *b == b'"').count() % 2 != 0)
}

pub(super) fn replacement(
    path: &str,
    original: Option<&str>,
    proposed: &str,
) -> Result<String, &'static str> {
    let original = original.ok_or(WITHHELD)?;
    if original.len() > 32 * 1024 || proposed.len() > 32 * 1024 {
        return Err(TOO_LARGE);
    }
    if original == proposed {
        return Err("No content change.");
    }
    if crate::context::Grammar::for_path(Path::new(path)).is_none()
        || sensitive(path)
        || [original, proposed]
            .iter()
            .any(|text| sensitive(text) || ambiguous(text))
    {
        return Err(WITHHELD);
    }
    let mut common_lines = 0;
    let mut start = 0;
    for (left, right) in original
        .split_inclusive('\n')
        .zip(proposed.split_inclusive('\n'))
    {
        if left != right {
            break;
        }
        common_lines += 1;
        start += left.len();
    }
    let left = &original[start..];
    let right = &proposed[start..];
    let suffix: usize = left
        .split_inclusive('\n')
        .rev()
        .zip(right.split_inclusive('\n').rev())
        .take_while(|(a, b)| a == b)
        .map(|(line, _)| line.len())
        .sum();
    let removed = &left[..left.len() - suffix];
    let added = &right[..right.len() - suffix];
    let old_count = removed.lines().count();
    let new_count = added.lines().count();
    if old_count + new_count > 64 || removed.len() + added.len() > 8192 {
        return Err(TOO_LARGE);
    }
    if !removed
        .split_inclusive('\n')
        .chain(added.split_inclusive('\n'))
        .all(source_line)
    {
        return Err(WITHHELD);
    }
    let old_start = common_lines + usize::from(old_count > 0);
    let new_start = common_lines + usize::from(new_count > 0);
    let mut patch = format!(
        "--- original\n+++ proposed\n@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
    );
    for (prefix, content) in [('-', removed), ('+', added)] {
        for line in content.split_inclusive('\n') {
            patch.push(prefix);
            patch.push_str(line);
            if !line.ends_with('\n') {
                patch.push_str("\n\\ No newline at end of file\n");
            }
        }
    }
    Ok(patch)
}
