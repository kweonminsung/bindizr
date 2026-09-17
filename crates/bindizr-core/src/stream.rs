//! Writing to stdout and stderr without dying on a closed pipe.
//!
//! `println!` panics when the reader stops early, which would make
//! `record list | head` exit 101 and `start 2>&1 | grep -m1 …` take the daemon
//! down. Everything bindizr prints goes through here instead.

use std::{
    io::{ErrorKind, Write},
    sync::atomic::{AtomicBool, Ordering},
};

/// Set once a reader is gone, so the rest of a long listing costs no failed
/// syscalls. Ending the process stays the entry point's call.
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
static STDERR_CLOSED: AtomicBool = AtomicBool::new(false);

/// Write to stdout, ignoring a closed pipe.
pub fn write_stdout(text: &str) {
    write(&STDOUT_CLOSED, &mut std::io::stdout(), text);
}

/// Write to stderr on the same terms; `2>&1` puts both on one pipe.
pub fn write_stderr(text: &str) {
    write(&STDERR_CLOSED, &mut std::io::stderr(), text);
}

/// Write unless this stream's reader already left.
fn write(closed: &AtomicBool, sink: &mut impl Write, text: &str) {
    if closed.load(Ordering::Relaxed) {
        return;
    }
    if let Err(e) = sink.write_all(text.as_bytes())
        && e.kind() == ErrorKind::BrokenPipe
    {
        closed.store(true, Ordering::Relaxed);
    }
}

/// `print!` for stdout.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::stream::write_stdout(&std::format!($($arg)*))
    };
}

/// `println!` for stdout.
#[macro_export]
macro_rules! outln {
    () => {
        $crate::stream::write_stdout("\n")
    };
    ($($arg:tt)*) => {
        $crate::stream::write_stdout(&std::format!("{}\n", std::format_args!($($arg)*)))
    };
}

/// `eprintln!` for stderr.
#[macro_export]
macro_rules! errln {
    ($($arg:tt)*) => {
        $crate::stream::write_stderr(&std::format!("{}\n", std::format_args!($($arg)*)))
    };
}
