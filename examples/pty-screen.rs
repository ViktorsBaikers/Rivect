//! Test oracle for the installed-client PTY tests; not shipped in a release.
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut dimension = || {
        args.next()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| (1..=1024).contains(value))
            .ok_or(io::ErrorKind::InvalidInput)
    };
    let mut screen = vt100::Parser::new(dimension()?, dimension()?, 0);
    let mut input = io::stdin().lock();
    let mut buffer = [0; 8192];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        screen.process(&buffer[..n]);
    }
    drop(input);
    io::stdout()
        .lock()
        .write_all(screen.screen().contents().as_bytes())
}
