//! Minimal ANSI coloring, honoring the NO_COLOR convention
//! (<https://no-color.org>) and disabled when stdout is not a terminal.

use std::{io::IsTerminal, sync::OnceLock};

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
            && std::io::stdout().is_terminal()
    })
}

fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

pub(crate) fn green(text: &str) -> String {
    paint("32", text)
}

pub(crate) fn red(text: &str) -> String {
    paint("31", text)
}

pub(crate) fn yellow(text: &str) -> String {
    paint("33", text)
}

pub(crate) fn cyan(text: &str) -> String {
    paint("36", text)
}
