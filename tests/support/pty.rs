//! Threadless PTY harness shared by the integration targets and the
//! in-crate card driver (`src/ui.rs` includes this file through `#[path]`).
//! One session owns its child and its root: the output is pumped by the
//! caller's own waits, so no reader thread can outlive a failed leg, and
//! teardown reaps the child before the root is removed.

use filedescriptor::FileDescriptor;
use portable_pty::PtySystem as _;
use portable_pty::{
    Child, ChildKiller, CommandBuilder, ExitStatus, MasterPty, NativePtySystem, PtySize,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The only parent environment a PTY child inherits, copied by value when
/// set (standards §10): the std list, the terminal kind and the dynamic
/// library search path cargo sets for the test process.
pub const PTY_ENV_ALLOWLIST: [&str; 8] = [
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "TMPDIR",
    "TERM",
    "LD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
];

/// Reads one pump pass may make. A harness transport quantum, not a
/// product cap: it keeps a flooding child from pinning one pass.
const PUMP_READS: usize = 16;
const PUMP_CHUNK: usize = 4096;
const POLL: Duration = Duration::from_millis(25);
const WAIT_POLL: Duration = Duration::from_millis(50);
const PTY_IO_DEADLINE: Duration = Duration::from_secs(10);

/// A command builder over a cleared environment plus the allowlisted keys
/// that are set in the parent.
pub fn pty_command(program: impl AsRef<OsStr>) -> CommandBuilder {
    let mut command = CommandBuilder::new(program);
    command.env_clear();
    for key in PTY_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
}

#[derive(Debug, thiserror::Error)]
pub enum PtySpawnError {
    #[error("pty {stage} failed")]
    Setup {
        stage: &'static str,
        source: io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum PtyIoError {
    #[error("pty read failed")]
    Read { source: io::Error },
    #[error("pty write failed")]
    Write { source: io::Error },
    #[error("pty write timed out")]
    Timeout { source: io::Error },
}

#[derive(Debug, thiserror::Error)]
pub enum PtyWaitError {
    #[error("pty child wait failed")]
    Wait { source: io::Error },
    #[error("pty child kill failed")]
    Kill { source: io::Error },
}

#[derive(Debug, thiserror::Error)]
pub enum PtyResizeError {
    #[error("pty resize failed")]
    Resize { source: io::Error },
}

#[derive(Debug, thiserror::Error)]
pub enum PtyTeardownError {
    #[error("pty child not reaped after termination; root kept at {}", root.display())]
    ChildNotReaped { root: PathBuf },
    #[error("pty child wait failed; root kept at {}", root.display())]
    ChildWait { root: PathBuf, source: PtyWaitError },
    #[error("pty child state unknown after a failed wait; root kept at {}", root.display())]
    ChildStateUnknown { root: PathBuf },
    #[error("pty root removal failed at {}; part of it may remain", root.display())]
    RootRemove { root: PathBuf, source: io::Error },
    #[error("pty output read failed")]
    Output { source: io::Error },
}

struct PtyOutput {
    reader: Box<dyn Read + Send>,
    stream: Vec<u8>,
    eof: bool,
    fault: Option<io::Error>,
}

#[derive(Debug, Clone, Copy)]
enum ReapState {
    Live,
    Terminated,
    Reaped(u32),
    Unknown,
}

/// One pass: at most [`PUMP_READS`] reads; ends early on end of stream, `WouldBlock`, or a non-transient read error
/// (`Interrupted` is retried in-pass); a stored fault is kept, not replaced, and later `pump` passes still read.
fn pump(output: &mut PtyOutput) {
    if output.eof {
        return;
    }
    let mut chunk = [0u8; PUMP_CHUNK];
    for _ in 0..PUMP_READS {
        match output.reader.read(&mut chunk) {
            Ok(0) => {
                output.eof = true;
                return;
            }
            Ok(read) => output.stream.extend_from_slice(&chunk[..read]),
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return,
                _ => {
                    // The first fault is the one the caller reports; later
                    // non-transient errors never replace it, and each one ends
                    // only this pass so later bounded passes may still drain.
                    if output.fault.is_none() {
                        output.fault = Some(error);
                    }
                    return;
                }
            },
        }
    }
}

fn take_fault(output: &mut PtyOutput) -> Result<(), PtyIoError> {
    match output.fault.take() {
        Some(source) => Err(PtyIoError::Read { source }),
        None => Ok(()),
    }
}

fn nap(deadline: Instant) {
    std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
}

fn report(error: &PtyTeardownError) {
    let mut stderr = io::stderr().lock();
    if let Err(write_error) = stderr.write_all(format!("{error}\n").as_bytes()) {
        std::hint::black_box(write_error);
    }
}

/// A Darwin probe measured concurrent `openpty` calls failing with errno -6;
/// locking only the creation call cleared it. This serializes this fixture's
/// own creation calls only — not the OS race globally — so revisit if Darwin
/// or portable-pty fixes it.
#[cfg(target_os = "macos")]
static OPENPTY: Mutex<()> = Mutex::new(());

pub struct PtySession {
    master: Box<dyn MasterPty + Send>,
    writer: FileDescriptor,
    output: RefCell<PtyOutput>,
    child: Box<dyn Child + Send + Sync>,
    state: ReapState,
    data_root: PathBuf,
    root: Option<TempDir>,
}

impl PtySession {
    /// # Errors
    /// Returns [`PtySpawnError`]; nothing was spawned and `root` drops
    /// normally.
    pub fn spawn(
        command: CommandBuilder,
        rows: u16,
        cols: u16,
        root: TempDir,
        data_root: PathBuf,
    ) -> Result<Self, PtySpawnError> {
        Self::open(command, rows, cols, root, data_root, None)
    }

    /// `spawn` with the child and reader behind injectable doubles.
    ///
    /// # Errors
    /// Returns [`PtySpawnError`] exactly as [`PtySession::spawn`] does.
    pub fn spawn_faulted(
        command: CommandBuilder,
        rows: u16,
        cols: u16,
        root: TempDir,
        data_root: PathBuf,
        faults: Arc<PtyFaults>,
    ) -> Result<Self, PtySpawnError> {
        Self::open(command, rows, cols, root, data_root, Some(faults))
    }

    fn open(
        command: CommandBuilder,
        rows: u16,
        cols: u16,
        root: TempDir,
        data_root: PathBuf,
        faults: Option<Arc<PtyFaults>>,
    ) -> Result<Self, PtySpawnError> {
        let setup = |stage: &'static str| {
            move |source: Box<dyn std::error::Error + Send + Sync>| PtySpawnError::Setup {
                stage,
                source: io::Error::other(source),
            }
        };
        let pair = {
            #[cfg(target_os = "macos")]
            let _creation = locked(&OPENPTY);
            NativePtySystem::default()
                .openpty(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|source| setup("open")(source.into()))?
        };
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|source| setup("reader")(source.into()))?;
        let Some(raw_fd) = pair.master.as_raw_fd() else {
            return Err(PtySpawnError::Setup {
                stage: "writer",
                source: io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the pty master has no raw descriptor",
                ),
            });
        };
        // The duplicate is the writer; `take_writer` is never called, so
        // no EOT write can happen on drop. FIONBIO sets the shared open
        // file description, so the reader clone is non-blocking too.
        let mut writer =
            FileDescriptor::dup(&raw_fd).map_err(|source| setup("writer")(source.into()))?;
        writer
            .set_non_blocking(true)
            .map_err(|source| setup("nonblocking")(source.into()))?;
        let child = pair
            .slave
            .spawn_command(command)
            .map_err(|source| setup("spawn")(source.into()))?;
        // From here to the returned session nothing is fallible.
        let (child, reader): (Box<dyn Child + Send + Sync>, Box<dyn Read + Send>) = match faults {
            Some(faults) => (
                Box::new(FaultChild {
                    inner: Some(child),
                    root: root.path().to_path_buf(),
                    faults: Arc::clone(&faults),
                }),
                Box::new(FaultReader {
                    inner: reader,
                    faults,
                }),
            ),
            None => (child, reader),
        };
        Ok(Self {
            master: pair.master,
            writer,
            output: RefCell::new(PtyOutput {
                reader,
                stream: Vec::new(),
                eof: false,
                fault: None,
            }),
            child,
            state: ReapState::Live,
            data_root,
            root: Some(root),
        })
    }

    pub fn data_root(&self) -> PathBuf {
        self.data_root.clone()
    }

    /// Resizes the pty under the live child: the kernel's winsize update
    /// plus the signal a real terminal sends when its window changes, which
    /// is what makes a live resize observable rather than a fresh spawn at
    /// another size.
    ///
    /// # Errors
    /// The pty refused the new size; the session is unchanged.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyResizeError> {
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|source| PtyResizeError::Resize {
                source: io::Error::other(source),
            })
    }

    /// Waits until `needle` is in the stream or the deadline passes.
    ///
    /// # Errors
    /// A stored read fault is returned before any success.
    pub fn wait_for(&mut self, needle: &[u8], timeout: Duration) -> Result<bool, PtyIoError> {
        let deadline = Instant::now() + timeout;
        loop {
            let output = self.output.get_mut();
            pump(output);
            take_fault(output)?;
            if find_subsequence(&output.stream, needle).is_some() {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            nap(deadline);
        }
    }

    /// The pumping replacement for a bare sleep.
    ///
    /// # Errors
    /// A stored read fault is returned at once, never behind a later `Ok`.
    pub fn pump_for(&mut self, duration: Duration) -> Result<(), PtyIoError> {
        let deadline = Instant::now() + duration;
        loop {
            let output = self.output.get_mut();
            pump(output);
            take_fault(output)?;
            if Instant::now() >= deadline {
                return Ok(());
            }
            nap(deadline);
        }
    }

    /// One pump pass without taking a stored fault, then whether `needle`
    /// is in the stream: bytes produced after a stored fault still land
    /// here, so a test can see that later passes kept reading.
    pub fn pump_pass(&mut self, needle: &[u8]) -> bool {
        let output = self.output.get_mut();
        pump(output);
        find_subsequence(&output.stream, needle).is_some()
    }

    /// Writes every byte or fails.
    ///
    /// # Errors
    /// [`PtyIoError::Timeout`] past the 10 s deadline, naming the bytes
    /// written out of the total; [`PtyIoError::Write`] otherwise.
    pub fn send(&mut self, bytes: &[u8]) -> Result<(), PtyIoError> {
        let deadline = Instant::now() + PTY_IO_DEADLINE;
        let total = bytes.len();
        let mut written = 0usize;
        while written < total {
            match self.writer.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(PtyIoError::Write {
                        source: io::Error::from(io::ErrorKind::WriteZero),
                    });
                }
                Ok(count) => written += count,
                Err(error) => self.retry_or_fail(error, deadline, written, total)?,
            }
        }
        loop {
            match self.writer.flush() {
                Ok(()) => return Ok(()),
                Err(error) => self.retry_or_fail(error, deadline, written, total)?,
            }
        }
    }

    fn retry_or_fail(
        &mut self,
        error: io::Error,
        deadline: Instant,
        written: usize,
        total: usize,
    ) -> Result<(), PtyIoError> {
        match error.kind() {
            io::ErrorKind::Interrupted => Ok(()),
            io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(PtyIoError::Timeout {
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("wrote {written} of {total} bytes"),
                        ),
                    });
                }
                pump(self.output.get_mut());
                nap(deadline);
                Ok(())
            }
            _ => Err(PtyIoError::Write { source: error }),
        }
    }

    /// A copy of the stream after one pump pass.
    ///
    /// # Errors
    /// A stored read fault.
    pub fn collected(&self) -> Result<Vec<u8>, PtyIoError> {
        let mut output = self.output.borrow_mut();
        pump(&mut output);
        take_fault(&mut output)?;
        Ok(output.stream.clone())
    }

    fn drain(&mut self, deadline: Instant) {
        loop {
            let output = self.output.get_mut();
            pump(output);
            if output.eof || output.fault.is_some() || Instant::now() >= deadline {
                return;
            }
            nap(deadline);
        }
    }

    /// Pumps and polls `try_wait`; never signals.
    fn reap_within(&mut self, deadline: Instant) -> Result<Option<u32>, PtyWaitError> {
        loop {
            pump(self.output.get_mut());
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.exit_code();
                    self.state = ReapState::Reaped(code);
                    self.drain(deadline);
                    return Ok(Some(code));
                }
                Ok(None) => {}
                Err(source) => {
                    self.state = ReapState::Unknown;
                    return Err(PtyWaitError::Wait { source });
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(WAIT_POLL.min(deadline - now));
        }
    }

    /// `Some` is reaped; `None` is a deadline that passed after one
    /// termination.
    ///
    /// # Errors
    /// An observed wait or kill failure.
    pub fn wait_exit(&mut self, timeout: Duration) -> Result<Option<u32>, PtyWaitError> {
        let deadline = Instant::now() + timeout;
        match self.state {
            ReapState::Reaped(code) => Ok(Some(code)),
            ReapState::Terminated | ReapState::Unknown => self.reap_within(deadline),
            ReapState::Live => {
                if let Some(code) = self.reap_within(deadline)? {
                    return Ok(Some(code));
                }
                match self.child.kill() {
                    Ok(()) => {
                        self.state = ReapState::Terminated;
                        Ok(None)
                    }
                    Err(source) => {
                        self.state = ReapState::Unknown;
                        Err(PtyWaitError::Kill { source })
                    }
                }
            }
        }
    }

    /// Reaps the child, then removes the root, then reports a stored
    /// output fault. A root is kept whenever the reap is unproven.
    fn teardown(&mut self) -> Vec<PtyTeardownError> {
        let mut errors = Vec::new();
        let Some(root) = self.root.take() else {
            return errors;
        };
        let reaped = match self.state {
            ReapState::Reaped(code) => Ok(Some(code)),
            ReapState::Unknown => {
                errors.push(PtyTeardownError::ChildStateUnknown { root: root.keep() });
                return self.finish_output(errors);
            }
            ReapState::Terminated => self.reap_within(Instant::now() + Duration::from_secs(10)),
            ReapState::Live => match self.wait_exit(Duration::from_secs(1)) {
                Ok(Some(code)) => Ok(Some(code)),
                Ok(None) => self.reap_within(Instant::now() + Duration::from_secs(10)),
                Err(source) => Err(source),
            },
        };
        match reaped {
            Ok(Some(_)) => {
                let path = root.keep();
                if let Err(source) = std::fs::remove_dir_all(&path) {
                    errors.push(PtyTeardownError::RootRemove { root: path, source });
                }
            }
            Ok(None) => errors.push(PtyTeardownError::ChildNotReaped { root: root.keep() }),
            Err(source) => errors.push(PtyTeardownError::ChildWait {
                root: root.keep(),
                source,
            }),
        }
        self.finish_output(errors)
    }

    fn finish_output(&mut self, mut errors: Vec<PtyTeardownError>) -> Vec<PtyTeardownError> {
        if let Some(source) = self.output.get_mut().fault.take() {
            errors.push(PtyTeardownError::Output { source });
        }
        errors
    }

    /// Success-path teardown.
    ///
    /// # Errors
    /// The first teardown failure; any further one goes to stderr.
    pub fn finish(mut self) -> Result<(), PtyTeardownError> {
        let mut errors = self.teardown().into_iter();
        let first = errors.next();
        for error in errors {
            report(&error);
        }
        first.map_or(Ok(()), Err)
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        for error in self.teardown() {
            report(&error);
        }
    }
}

pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Cell-boundary artifacts can widen a rendered space; assertions match
/// on whitespace-normalized text so wrapped and reflowed rows still
/// compare equal across viewports.
pub fn squashed(screen: &str) -> String {
    screen.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Observation and fault switches shared with the doubles
/// [`PtySession::spawn_faulted`] installs at construction.
#[derive(Debug, Default)]
pub struct PtyFaults {
    pub fail_try_wait: AtomicBool,
    /// Read faults in arming order; the reader reports the front and leaves
    /// the rest queued, so each arming can carry its own message.
    read_faults: Mutex<VecDeque<&'static str>>,
    pub kills: AtomicUsize,
    pub root_at_first_reap: Mutex<Option<bool>>,
    pub parked_child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
}

impl PtyFaults {
    /// Arms one injected read fault: the next read reports `message`.
    pub fn fail_next_read(&self, message: &'static str) {
        locked(&self.read_faults).push_back(message);
    }

    /// Read faults still waiting for a read.
    pub fn armed_read_faults(&self) -> usize {
        locked(&self.read_faults).len()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn released() -> io::Error {
    io::Error::other("fault child released")
}

#[derive(Debug)]
struct FaultChild {
    inner: Option<Box<dyn Child + Send + Sync>>,
    root: PathBuf,
    faults: Arc<PtyFaults>,
}

impl ChildKiller for FaultChild {
    fn kill(&mut self) -> io::Result<()> {
        self.faults.kills.fetch_add(1, Ordering::SeqCst);
        match self.inner.as_mut() {
            Some(inner) => inner.kill(),
            None => Err(released()),
        }
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        Box::new(FaultKiller {
            inner: self.inner.as_ref().map(|inner| inner.clone_killer()),
            faults: Arc::clone(&self.faults),
        })
    }
}

impl Child for FaultChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.faults.fail_try_wait.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected try_wait fault"));
        }
        let Some(inner) = self.inner.as_mut() else {
            return Err(released());
        };
        let status = inner.try_wait()?;
        if status.is_some() {
            let mut slot = locked(&self.faults.root_at_first_reap);
            if slot.is_none() {
                *slot = Some(self.root.exists());
            }
        }
        Ok(status)
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        match self.inner.as_mut() {
            Some(inner) => inner.wait(),
            None => Err(released()),
        }
    }

    fn process_id(&self) -> Option<u32> {
        self.inner.as_ref().and_then(|inner| inner.process_id())
    }
}

impl Drop for FaultChild {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            *locked(&self.faults.parked_child) = Some(inner);
        }
    }
}

#[derive(Debug)]
struct FaultKiller {
    inner: Option<Box<dyn ChildKiller + Send + Sync>>,
    faults: Arc<PtyFaults>,
}

impl ChildKiller for FaultKiller {
    fn kill(&mut self) -> io::Result<()> {
        self.faults.kills.fetch_add(1, Ordering::SeqCst);
        match self.inner.as_mut() {
            Some(inner) => inner.kill(),
            None => Err(released()),
        }
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        Box::new(Self {
            inner: self.inner.as_ref().map(|inner| inner.clone_killer()),
            faults: Arc::clone(&self.faults),
        })
    }
}

struct FaultReader {
    inner: Box<dyn Read + Send>,
    faults: Arc<PtyFaults>,
}

impl Read for FaultReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let message = locked(&self.faults.read_faults).pop_front();
        if let Some(message) = message {
            return Err(io::Error::other(message));
        }
        self.inner.read(buf)
    }
}

/// Reconstructs the visible frame from collected PTY bytes: the ANSI
/// subset the TUI emits — cursor addressing, erase-in-line/display,
/// scroll regions and scroll/insert/delete line and character operations,
/// CR/LF, printable cells — flattened to `rows` x `cols` text lines.
/// OSC payloads and private modes carry no cells and are skipped.
pub fn reconstruct_screen(bytes: &[u8], rows: usize, cols: usize) -> String {
    let mut cells = vec![vec![b' '; cols]; rows];
    let mut row = 0usize;
    let mut col = 0usize;
    // DECSTBM scrolling region, inclusive; the whole screen by default.
    let mut top = 0usize;
    let mut bottom = rows - 1;
    let mut index = 0usize;

    // Scroll the region up/down by n lines (CSI S / CSI T, and a newline at
    // the bottom margin): lines move toward the top/bottom and the vacated
    // rows blank. rotate moves the row vectors, not the cells.
    fn scroll_up(cells: &mut [Vec<u8>], top: usize, bottom: usize, n: usize) {
        let region = &mut cells[top..=bottom];
        let len = region.len();
        let n = n.min(len);
        region.rotate_left(n);
        for line in &mut region[len - n..] {
            line.fill(b' ');
        }
    }
    fn scroll_down(cells: &mut [Vec<u8>], top: usize, bottom: usize, n: usize) {
        let region = &mut cells[top..=bottom];
        let n = n.min(region.len());
        region.rotate_right(n);
        for line in &mut region[..n] {
            line.fill(b' ');
        }
    }

    while index < bytes.len() {
        match bytes[index] {
            b'\x1b' => {
                index += 1;
                if index >= bytes.len() {
                    break;
                }
                match bytes[index] {
                    b'[' => {
                        index += 1;
                        let params_start = index;
                        while index < bytes.len() && !(0x40..=0x7e).contains(&bytes[index]) {
                            index += 1;
                        }
                        if index == bytes.len() {
                            break;
                        }
                        let final_byte = bytes[index];
                        let params = &bytes[params_start..index];
                        index += 1;
                        // Private/secondary-prefixed modes (DEC private modes,
                        // > / =) carry no cell effect here.
                        if matches!(params.first(), Some(b'?') | Some(b'>') | Some(b'=')) {
                            continue;
                        }
                        let parameters = params
                            .split(|byte| *byte == b';')
                            .map(|parameter| {
                                if parameter.is_empty() {
                                    None
                                } else {
                                    std::str::from_utf8(parameter)
                                        .ok()
                                        .and_then(|value| value.parse::<usize>().ok())
                                }
                            })
                            .collect::<Vec<_>>();
                        let parameter = |position: usize, default: usize| {
                            parameters
                                .get(position)
                                .and_then(|value| *value)
                                .unwrap_or(default)
                        };
                        match final_byte {
                            b'H' | b'f' => {
                                row = parameter(0, 1).max(1).saturating_sub(1).min(rows - 1);
                                col = parameter(1, 1).max(1).saturating_sub(1).min(cols - 1);
                            }
                            b'A' => row = row.saturating_sub(parameter(0, 1).max(1)),
                            b'B' => row = row.saturating_add(parameter(0, 1).max(1)).min(rows - 1),
                            b'C' | b'a' => {
                                col = col.saturating_add(parameter(0, 1).max(1)).min(cols - 1)
                            }
                            b'D' => col = col.saturating_sub(parameter(0, 1).max(1)),
                            b'G' => col = parameter(0, 1).max(1).saturating_sub(1).min(cols - 1),
                            b'd' => row = parameter(0, 1).max(1).saturating_sub(1).min(rows - 1),
                            b'E' => {
                                row = row.saturating_add(parameter(0, 1).max(1)).min(rows - 1);
                                col = 0;
                            }
                            b'F' => {
                                row = row.saturating_sub(parameter(0, 1).max(1));
                                col = 0;
                            }
                            b'J' => match parameter(0, 0) {
                                0 => {
                                    for cell in &mut cells[row][col..] {
                                        *cell = b' ';
                                    }
                                    for line in cells.iter_mut().skip(row + 1) {
                                        line.fill(b' ');
                                    }
                                }
                                1 => {
                                    for line in cells.iter_mut().take(row) {
                                        line.fill(b' ');
                                    }
                                    for cell in &mut cells[row][..=col] {
                                        *cell = b' ';
                                    }
                                }
                                2 | 3 => {
                                    for line in &mut cells {
                                        line.fill(b' ');
                                    }
                                }
                                _ => {}
                            },
                            b'K' => match parameter(0, 0) {
                                0 => cells[row][col..].fill(b' '),
                                1 => cells[row][..=col].fill(b' '),
                                2 => cells[row].fill(b' '),
                                _ => {}
                            },
                            // ECH: erase n cells from the cursor, no move.
                            b'X' => {
                                let end = (col + parameter(0, 1).max(1)).min(cols);
                                cells[row][col..end].fill(b' ');
                            }
                            // ICH: insert n blanks at the cursor, shifting the
                            // rest of the row right (cells past the edge drop).
                            b'@' => {
                                let n = parameter(0, 1).max(1).min(cols - col);
                                if n > 0 {
                                    let line = &mut cells[row];
                                    line.copy_within(col..cols - n, col + n);
                                    line[col..col + n].fill(b' ');
                                }
                            }
                            // DCH: delete n cells at the cursor, pulling the
                            // rest of the row left.
                            b'P' => {
                                let n = parameter(0, 1).max(1).min(cols - col);
                                if n > 0 {
                                    let line = &mut cells[row];
                                    line.copy_within(col + n..cols, col);
                                    line[cols - n..].fill(b' ');
                                }
                            }
                            // IL / DL: insert/delete n whole lines at the cursor
                            // within the scrolling region.
                            b'L' => {
                                if row >= top && row <= bottom {
                                    let region = &mut cells[row..=bottom];
                                    let n = parameter(0, 1).max(1).min(region.len());
                                    region.rotate_right(n);
                                    for line in &mut region[..n] {
                                        line.fill(b' ');
                                    }
                                }
                            }
                            b'M' => {
                                if row >= top && row <= bottom {
                                    let region = &mut cells[row..=bottom];
                                    let len = region.len();
                                    let n = parameter(0, 1).max(1).min(len);
                                    region.rotate_left(n);
                                    for line in &mut region[len - n..] {
                                        line.fill(b' ');
                                    }
                                }
                            }
                            b'S' => scroll_up(&mut cells, top, bottom, parameter(0, 1).max(1)),
                            b'T' => scroll_down(&mut cells, top, bottom, parameter(0, 1).max(1)),
                            // DECSTBM: set the scrolling region and home the
                            // cursor to its top-left.
                            b'r' => {
                                let t = parameter(0, 1).max(1).saturating_sub(1).min(rows - 1);
                                let b = parameter(1, rows).max(1).saturating_sub(1).min(rows - 1);
                                if t < b {
                                    top = t;
                                    bottom = b;
                                }
                                row = top;
                                col = 0;
                            }
                            _ => {}
                        }
                        continue;
                    }
                    // OSC (title etc.): skip to BEL or ST so its payload never
                    // paints cells.
                    b']' => {
                        index += 1;
                        while index < bytes.len() {
                            if bytes[index] == 0x07 {
                                index += 1;
                                break;
                            }
                            if bytes[index] == 0x1b
                                && index + 1 < bytes.len()
                                && bytes[index + 1] == b'\\'
                            {
                                index += 2;
                                break;
                            }
                            index += 1;
                        }
                        continue;
                    }
                    // RI: reverse index — scroll down at the top margin.
                    b'M' => {
                        if row == top {
                            scroll_down(&mut cells, top, bottom, 1);
                        } else {
                            row = row.saturating_sub(1);
                        }
                        index += 1;
                        continue;
                    }
                    // Charset designation (ESC ( B etc.): skip the designator.
                    b'(' | b')' | b'*' | b'+' => {
                        index += 2;
                        continue;
                    }
                    _ => {
                        index += 1;
                        continue;
                    }
                }
            }
            b'\r' => col = 0,
            // The harness models ratatui's absolute-positioned repaints, which
            // never scroll by newline; a newline advances the row and clamps at
            // the bottom so a stray LF cannot shift a painted status line.
            // Explicit scrolls (CSI S/T) and insert/delete lines still model
            // the scrolling region above.
            b'\n' => row = (row + 1).min(rows - 1),
            b'\x08' => col = col.saturating_sub(1),
            byte if (0x20..=0x7e).contains(&byte) => {
                cells[row][col] = byte;
                col = (col + 1).min(cols - 1);
            }
            // A non-ASCII UTF-8 grapheme still occupies terminal cells —
            // the recon is ASCII-only so the glyph itself isn't drawn,
            // but the cursor MUST advance by the grapheme's real cell
            // width or every later cell on the row shifts left and
            // repaints collide into ghosts.
            byte if byte >= 0x80 => {
                use ratatui::buffer::CellWidth as _;
                let len = match byte {
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    0xF0..=0xF7 => 4,
                    // A lone continuation byte: decode fails, step one.
                    _ => 1,
                };
                let end = (index + len).min(bytes.len());
                let width = std::str::from_utf8(&bytes[index..end])
                    .ok()
                    .map(|seq| seq.cell_width())
                    .unwrap_or(1);
                col = col.saturating_add(usize::from(width)).min(cols - 1);
                index += len - 1;
            }
            _ => {}
        }
        index += 1;
    }

    cells
        .iter()
        .map(|line| {
            String::from_utf8_lossy(line)
                .trim_end_matches(' ')
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Re-renders the reconstructed frame until `needle` is on screen or the
/// deadline passes; returns the final frame either way so the assertion
/// prints what the operator actually saw.
///
/// # Errors
/// A transport fault from [`PtySession::collected`], even when `needle`
/// is already in the stream.
pub fn wait_for_screen_text(
    pty: &PtySession,
    rows: usize,
    cols: usize,
    needle: &str,
    timeout: Duration,
) -> Result<String, PtyIoError> {
    let deadline = Instant::now() + timeout;
    let mut visible = reconstruct_screen(&pty.collected()?, rows, cols);
    while !visible.contains(needle) && Instant::now() < deadline {
        std::thread::sleep(POLL);
        visible = reconstruct_screen(&pty.collected()?, rows, cols);
    }
    Ok(visible)
}

#[cfg(test)]
mod screen_recon_tests {
    use super::reconstruct_screen;

    fn screen(bytes: &[u8], rows: usize, cols: usize) -> Vec<String> {
        reconstruct_screen(bytes, rows, cols)
            .split('\n')
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn scroll_up_shifts_lines_and_blanks_the_bottom() {
        let out = screen(b"AAA\r\nBBB\r\nCCC\x1b[1S", 3, 3);
        assert_eq!(out, vec!["BBB", "CCC", ""]);
    }

    #[test]
    fn scroll_down_shifts_lines_and_blanks_the_top() {
        let out = screen(b"AAA\r\nBBB\r\nCCC\x1b[1T", 3, 3);
        assert_eq!(out, vec!["", "AAA", "BBB"]);
    }

    #[test]
    fn newline_clamps_at_the_bottom_row() {
        // The painted-frame model clamps a stray newline at the bottom rather
        // than scrolling, so a status line stays put; explicit CSI S/T scroll.
        let out = screen(b"AAA\r\nBBB\r\nCCC\r\nDDD", 3, 3);
        assert_eq!(out, vec!["AAA", "BBB", "DDD"]);
    }

    #[test]
    fn insert_line_pushes_the_region_down() {
        let out = screen(b"AAA\r\nBBB\r\nCCC\x1b[2;1H\x1b[1L", 3, 3);
        assert_eq!(out, vec!["AAA", "", "BBB"]);
    }

    #[test]
    fn delete_line_pulls_the_region_up() {
        let out = screen(b"AAA\r\nBBB\r\nCCC\x1b[2;1H\x1b[1M", 3, 3);
        assert_eq!(out, vec!["AAA", "CCC", ""]);
    }

    #[test]
    fn scrolling_region_confines_the_scroll() {
        let out = screen(b"AAA\r\nBBB\r\nCCC\x1b[2;3r\x1b[1S", 3, 3);
        assert_eq!(out, vec!["AAA", "CCC", ""]);
    }

    #[test]
    fn osc_payload_never_paints_cells() {
        let out = screen(b"AB\x1b]0;title\x07CD", 1, 4);
        assert_eq!(out, vec!["ABCD"]);
    }

    #[test]
    fn insert_and_delete_characters_shift_the_row() {
        let out = screen(b"ABCD\x1b[1;2H\x1b[2@", 1, 6);
        assert_eq!(out, vec!["A  BCD"]);
        let out = screen(b"ABCD\x1b[1;2H\x1b[2P", 1, 4);
        assert_eq!(out, vec!["AD"]);
    }
}
