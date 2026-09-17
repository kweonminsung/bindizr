//! Writing to stdout and stderr without dying on a closed pipe.
//!
//! `println!` panics when the reader stops early, which would make
//! `record list | head` exit 101 and `start 2>&1 | grep -m1 …` take the daemon
//! down. Everything bindizr prints goes through here instead.

use std::{
    io::{ErrorKind, Write},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Set once a reader is gone, so the rest of a long listing costs no failed
/// syscalls. Ending the process stays the entry point's call.
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
static STDERR_CLOSED: AtomicBool = AtomicBool::new(false);

/// The first failure that was not a closed pipe, such as a full disk. Output
/// is lost, so the entry point reports it instead of exiting as success.
static WRITE_FAILURE: OnceLock<String> = OnceLock::new();

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
    let Err(e) = sink.write_all(text.as_bytes()) else {
        return;
    };
    // Either way this stream is done; only a closed pipe is success.
    closed.store(true, Ordering::Relaxed);
    if e.kind() != ErrorKind::BrokenPipe {
        let _ = WRITE_FAILURE.set(e.to_string());
    }
}

/// The failure that lost output, for the entry point to report; a closed pipe
/// is not one.
pub fn write_failure() -> Option<&'static str> {
    WRITE_FAILURE.get().map(String::as_str)
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

#[cfg(test)]
mod tests {
    use std::{
        io::{Error, ErrorKind, Write},
        sync::atomic::AtomicBool,
    };

    use super::*;

    /// A sink whose every write fails with one kind.
    struct FailingSink(ErrorKind);

    impl Write for FailingSink {
        /// Fail with this sink's kind.
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(Error::new(self.0, "sink failed"))
        }

        /// Nothing is buffered.
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Verify that a closed pipe is quiet while any other failure is kept.
    #[test]
    fn a_closed_pipe_is_success_and_a_real_failure_is_not() {
        let closed = AtomicBool::new(false);
        write(&closed, &mut FailingSink(ErrorKind::BrokenPipe), "x");
        assert!(
            closed.load(Ordering::Relaxed),
            "the stream is done either way"
        );
        assert_eq!(write_failure(), None, "the reader chose to stop");

        let closed = AtomicBool::new(false);
        write(&closed, &mut FailingSink(ErrorKind::StorageFull), "x");
        assert!(closed.load(Ordering::Relaxed));
        assert!(
            write_failure().is_some_and(|e| e.contains("sink failed")),
            "lost output must be reported: {:?}",
            write_failure()
        );
    }
}
