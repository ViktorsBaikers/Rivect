//! Independent, release-pinned foreground terminal confirmation.

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::Serialize;
use serde_json::Value;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[derive(Serialize)]
struct Decision<'a> {
    question: &'a Value,
    params: &'a Value,
    consent_delay_ms: u128,
}

/// Only the fresh verified renderer receives the other endpoint. Requester
/// disconnect takes priority even when the witness response is already buffered.
///
/// # Errors
/// Returns an error if the pinned child, its channel or controlling terminal fails.
pub fn confirm(question: &Value, params: &Value) -> io::Result<bool> {
    if !io::stderr().is_terminal() {
        return Ok(false);
    }
    let (mut channel, renderer) = UnixStream::pair()?;
    channel.set_write_timeout(Some(Duration::from_secs(5)))?;
    let pin = option_env!("RIVECT_BUNDLED_UI_SHA256")
        .ok_or_else(|| io::Error::other("no paired terminal client"))?;
    let mut child = super::spawn_terminal_witness(pin, renderer.into())?;
    let verdict = (|| -> io::Result<bool> {
        let frame = Decision {
            question,
            params,
            consent_delay_ms: crate::ui::DECISION_CONSENT_DELAY.as_millis(),
        };
        serde_json::to_writer(&mut channel, &frame)?;
        channel.write_all(b"\n")?;
        let requester = io::stdin();
        let mut fds = [
            PollFd::new(&requester, PollFlags::empty()),
            PollFd::new(&channel, PollFlags::IN),
        ];
        if poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 300,
                tv_nsec: 0,
            }),
        )? == 0
            || !fds[0].revents().is_empty()
        {
            return Ok(false);
        }
        let mut response = [0_u8; 1];
        let accepted = channel.read(&mut response)? == 1 && response == *b"Y";
        drop(channel);
        Ok(accepted)
    })();
    if !matches!(verdict, Ok(true)) && child.try_wait()?.is_none() {
        child.kill()?;
    }
    let status = child.wait()?;
    let requester = io::stdin();
    let mut fds = [PollFd::new(&requester, PollFlags::empty())];
    poll(
        &mut fds,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    Ok(verdict? && status.success() && fds[0].revents().is_empty())
}
