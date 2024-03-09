pub fn info() -> String {
    format!(
        "Whisper TUN/TAP Wisp Proxy version {}\n\
        Copyright (C) 2024 Endercass <https://github.com/Endercass>\n\
        Licensed under GNU GPL-3.0-or-later\n\
        Source code is available at:\n\
        <https://github.com/Endercass/whisper>",
        env!("CARGO_PKG_VERSION"),
    )
}
