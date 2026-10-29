//! Instruction file discovery (AC-076, REQ-063): four candidate names per
//! scope, two folded slots, one load per file identity, and a typed conflict
//! when two different files declare one slot in one scope.
//!
//! Instruction files are data, never authority (§14.8): a loaded file
//! contributes its text, its path and its scope to the request. Nothing here
//! interprets that text, and no discovery path can add a grant, a hook or a
//! tool — the fold is a pure function of the *name*, compared before any file
//! is opened, so discovery never depends on how a filesystem folds case.

use crate::contracts::ErrorCode;
use crate::executor::FileIdentity;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The capped read. An instruction file is untrusted input to the request, so
/// its bytes are bounded like every other external document.
pub const INSTRUCTION_FILE_MAX_BYTES: usize = 64 * 1024;

/// One instruction slot: the logical name two candidate spellings fold into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstructionSlot {
    Agent,
    Claude,
}

impl InstructionSlot {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Claude => "claude",
        }
    }
}

/// The four candidate names, canonical before alias, each with the slot it
/// declares (I9). This table is the fold: `AGENTS.md` and `agent.md` declare
/// one slot, `CLAUDE.md` and `claude.md` the other.
pub const INSTRUCTION_FILES: [(&str, InstructionSlot); 4] = [
    ("AGENTS.md", InstructionSlot::Agent),
    ("CLAUDE.md", InstructionSlot::Claude),
    ("agent.md", InstructionSlot::Agent),
    ("claude.md", InstructionSlot::Claude),
];

/// The slot a candidate name declares, or `None` for any other name — the fold
/// as a total function of the name alone.
#[must_use]
pub fn fold(name: &str) -> Option<InstructionSlot> {
    INSTRUCTION_FILES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, slot)| *slot)
}

/// One discovered instruction file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionEntry {
    pub slot: InstructionSlot,
    /// The name that was found — the canonical spelling when an alias reached
    /// the same file.
    pub name: String,
    pub path: PathBuf,
    /// The scope the file was found in.
    pub scope: PathBuf,
    /// The text, verbatim: data the request carries, never an instruction the
    /// executor follows.
    pub text: String,
}

/// Two different files declaring one slot in one scope: one typed record, so
/// neither source is dropped and neither silently wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionConflict {
    pub slot: InstructionSlot,
    pub scope: PathBuf,
    /// Every distinct file that declared the slot here, canonical first.
    pub sources: Vec<PathBuf>,
}

impl std::fmt::Display for InstructionConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sources = self
            .sources
            .iter()
            .map(|source| source.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "conflicting {} instruction files in {}: {sources}",
            self.slot.as_str(),
            self.scope.display()
        )
    }
}

/// What one discovery found: every distinct file once, inner scope first, and
/// the conflicts that made two sources visible instead of picking one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstructionSet {
    pub entries: Vec<InstructionEntry>,
    pub conflicts: Vec<InstructionConflict>,
}

/// One candidate file found on disk, before the fold decides which name wins.
struct Candidate {
    depth: usize,
    position: usize,
    name: &'static str,
    slot: InstructionSlot,
    path: PathBuf,
    /// The resolved target the read opens: the name is followed once, and the
    /// target stayed beneath its own scope when it was followed.
    resolved: PathBuf,
    identity: FileIdentity,
}

impl InstructionSet {
    /// Discovers the instruction files of a scope chain. `scopes` runs from
    /// the outermost scope to the innermost, so the result orders the
    /// innermost first: an inner scope wins its slot over an outer one.
    ///
    /// Every candidate is confined to the scope it was found in: the name is
    /// resolved, the target must stay beneath that scope, and only a regular
    /// file is opened — a name is a name, never a redirect out of the scope.
    ///
    /// # Errors
    /// Returns the typed read failure of a file that exists but cannot be
    /// observed, read, or bounded, and the typed refusal of a name whose
    /// target leaves its scope or is not a regular file — a candidate is never
    /// skipped silently.
    pub fn discover(scopes: &[PathBuf]) -> Result<Self, InstructionError> {
        let mut candidates = Vec::new();
        for (depth, scope) in scopes.iter().enumerate() {
            // The scope the candidates are confined to resolves first, so the
            // confinement compares two resolved paths.
            let resolved_scope = match scope.canonicalize() {
                Ok(resolved) => resolved,
                // A scope that is not on disk holds no candidate, exactly like
                // a missing name.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(InstructionError::Metadata {
                        path: scope.clone(),
                        source,
                    });
                }
            };
            for (position, (name, slot)) in INSTRUCTION_FILES.iter().enumerate() {
                let path = scope.join(name);
                let Some((resolved, identity)) = confined_candidate(&path, &resolved_scope)? else {
                    continue;
                };
                candidates.push(Candidate {
                    depth,
                    position,
                    name,
                    slot: *slot,
                    path,
                    resolved,
                    identity,
                });
            }
        }
        candidates.sort_by_key(|candidate| (candidate.depth, candidate.slot, candidate.position));

        let mut found: Vec<(usize, usize, InstructionEntry)> = Vec::new();
        let mut conflicts = Vec::new();
        for group in
            candidates.chunk_by(|left, right| left.depth == right.depth && left.slot == right.slot)
        {
            let slot = group[0].slot;
            let depth = group[0].depth;
            // One file loads once (I9): two names reaching one file identity
            // are one source, and the canonical name is the one kept.
            let mut kept: Vec<&Candidate> = Vec::new();
            for candidate in group {
                if kept.iter().any(|seen| seen.identity == candidate.identity) {
                    continue;
                }
                kept.push(candidate);
            }
            if kept.len() > 1 {
                conflicts.push(InstructionConflict {
                    slot,
                    scope: scopes
                        .get(depth)
                        .cloned()
                        .unwrap_or_else(|| PathBuf::from(".")),
                    sources: kept
                        .iter()
                        .map(|candidate| candidate.path.clone())
                        .collect(),
                });
            }
            for candidate in kept {
                found.push((
                    candidate.depth,
                    candidate.position,
                    InstructionEntry {
                        slot: candidate.slot,
                        name: candidate.name.to_string(),
                        path: candidate.path.clone(),
                        scope: scopes
                            .get(candidate.depth)
                            .cloned()
                            .unwrap_or_else(|| PathBuf::from(".")),
                        text: read_instruction(&candidate.resolved, &candidate.path)?,
                    },
                ));
            }
        }

        // Innermost scope first, then the name table's own order: precedence
        // is a pure function of the chain and the fold, never of directory
        // listing order.
        found.sort_by_key(|(depth, position, _)| (std::cmp::Reverse(*depth), *position));
        Ok(Self {
            entries: found.into_iter().map(|(_, _, entry)| entry).collect(),
            conflicts,
        })
    }

    /// The entry a slot resolves to: the innermost scope wins, and inside one
    /// scope the canonical name precedes its alias.
    #[must_use]
    pub fn effective(&self, slot: InstructionSlot) -> Option<&InstructionEntry> {
        self.entries.iter().find(|entry| entry.slot == slot)
    }
}

/// One candidate name resolved and confined to its own scope: the name is
/// followed to its target, the target must stay beneath the scope it was found
/// in, and the target's own descriptor must name a regular file. A link out of
/// its scope is therefore a typed refusal instead of a read of a file the
/// scope never owned, and a FIFO target can never wait on an open that needs a
/// writer. An absent name — and a link that resolves nowhere — is not a
/// candidate.
fn confined_candidate(
    path: &Path,
    scope: &Path,
) -> Result<Option<(PathBuf, FileIdentity)>, InstructionError> {
    let resolved = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(InstructionError::Metadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !resolved.starts_with(scope) {
        return Err(InstructionError::OutOfScope {
            path: path.to_path_buf(),
            scope: scope.to_path_buf(),
        });
    }
    let (_file, metadata) = open_regular(&resolved, path)?;
    Ok(Some((resolved, FileIdentity::from_metadata(&metadata))))
}

/// One checked open (the ingress `read_user_config` shares its shape): the
/// opened descriptor is the one whose metadata must name a regular file, so a
/// link or a FIFO swapped onto the resolved path after the confinement check
/// can neither redirect the read nor hang it. `path` is the name the caller
/// reported, which every typed failure names.
fn open_regular(
    resolved: &Path,
    path: &Path,
) -> Result<(std::fs::File, std::fs::Metadata), InstructionError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let read_failed = |source: std::io::Error| InstructionError::Read {
        path: path.to_path_buf(),
        source,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            rivect_sandbox_helper::ANCHOR_O_NOFOLLOW | rivect_sandbox_helper::OPEN_NONBLOCK,
        )
        .open(resolved)
        .map_err(read_failed)?;
    let metadata = file.metadata().map_err(read_failed)?;
    if !metadata.is_file() {
        return Err(InstructionError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    Ok((file, metadata))
}

fn read_instruction(resolved: &Path, path: &Path) -> Result<String, InstructionError> {
    let (file, _metadata) = open_regular(resolved, path)?;
    let mut raw = Vec::new();
    let mut capped = file.take(INSTRUCTION_FILE_MAX_BYTES as u64 + 1);
    capped
        .read_to_end(&mut raw)
        .map_err(|source| InstructionError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if raw.len() > INSTRUCTION_FILE_MAX_BYTES {
        return Err(InstructionError::TooLarge {
            path: path.to_path_buf(),
            limit: INSTRUCTION_FILE_MAX_BYTES,
        });
    }
    String::from_utf8(raw).map_err(|_not_text| InstructionError::NotText {
        path: path.to_path_buf(),
    })
}

/// Failures of one discovery. A candidate that exists but cannot be loaded is
/// a typed failure, never a silently skipped instruction.
#[derive(Debug, thiserror::Error)]
pub enum InstructionError {
    #[error("instruction file {} could not be observed: {source}", path.display())]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("instruction file {} could not be read: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("instruction file {} is larger than {limit} bytes", path.display())]
    TooLarge { path: PathBuf, limit: usize },
    #[error("instruction file {} is not text", path.display())]
    NotText { path: PathBuf },
    #[error(
        "instruction file {} resolves outside its scope {}",
        path.display(),
        scope.display()
    )]
    OutOfScope { path: PathBuf, scope: PathBuf },
    #[error("instruction file {} is not a regular file", path.display())]
    NotRegular { path: PathBuf },
}

impl InstructionError {
    /// The wire code this failure reports (P-001): an unreadable input is a
    /// blocked dependency, a candidate that left its scope is a denial, and a
    /// non-text or non-regular file is invalid input.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Metadata { .. } | Self::Read { .. } | Self::TooLarge { .. } => {
                ErrorCode::DependencyBlocked
            }
            Self::OutOfScope { .. } => ErrorCode::Denied,
            Self::NotText { .. } | Self::NotRegular { .. } => ErrorCode::InvalidInput,
        }
    }
}
