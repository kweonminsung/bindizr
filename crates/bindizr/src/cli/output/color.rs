//! Minimal ANSI coloring, honoring the NO_COLOR convention
//! (<https://no-color.org>) and disabled when stdout is not a terminal.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::{env, io};

/// Return whether terminal output should use ANSI colors.
fn is_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        env::var_os("NO_COLOR").is_none_or(|value| value.is_empty()) && io::stdout().is_terminal()
    })
}

/// Wrap text in the requested ANSI color, or leave it unchanged when colors
/// are disabled.
fn colored(code: &str, text: &str) -> String {
    if is_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Format text in green when colors are enabled.
pub(crate) fn green(text: &str) -> String {
    colored("32", text)
}

/// Format text in red when colors are enabled.
pub(crate) fn red(text: &str) -> String {
    colored("31", text)
}

/// Format text in yellow when colors are enabled.
pub(crate) fn yellow(text: &str) -> String {
    colored("33", text)
}

/// Format text in cyan when colors are enabled.
pub(crate) fn cyan(text: &str) -> String {
    colored("36", text)
}
