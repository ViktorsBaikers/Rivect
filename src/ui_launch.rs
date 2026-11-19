//! Interactive release handoff. Neither a wire flag nor a caller-provided fd is human consent.

pub use rivect::executor::terminal_witness::confirm;
use std::io;
use std::path::Path;

const PIN: Option<&str> = option_env!("RIVECT_BUNDLED_UI_SHA256");

fn pin() -> io::Result<&'static str> {
    PIN.ok_or_else(|| io::Error::other("this core has no paired terminal client"))
}

pub fn paired_terminal_parent() -> io::Result<()> {
    rivect::executor::paired_terminal_parent(pin()?).map(drop)
}

pub fn exec(args: &[&str], root: Option<&Path>) -> io::Error {
    match pin() {
        Ok(pin) => rivect::executor::exec_terminal_client(pin, args, root),
        Err(error) => error,
    }
}
