//! Minimal stub of the `os_info` public API used by `grammers-client`.
//!
//! See Cargo.toml for rationale.  We expose only the three methods
//! grammers actually calls: `get()`, `Info::os_type`, `Info::bitness`,
//! `Info::version`.

use std::fmt;

/// Returns a static `Info` — the values are informational only.
pub fn get() -> Info {
    Info
}

#[derive(Debug, Clone, Copy)]
pub struct Info;

impl Info {
    /// "iOS", "Linux", "Android"… — we just use the Rust target name.
    pub fn os_type(&self) -> Type {
        Type
    }

    pub fn bitness(&self) -> Bitness {
        #[cfg(target_pointer_width = "64")]
        { Bitness::X64 }
        #[cfg(target_pointer_width = "32")]
        { Bitness::X32 }
    }

    pub fn version(&self) -> Version {
        Version
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Type;

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(target_os = "ios")]       return f.write_str("iOS");
        #[cfg(target_os = "macos")]     return f.write_str("macOS");
        #[cfg(target_os = "android")]   return f.write_str("Android");
        #[cfg(target_os = "linux")]     return f.write_str("Linux");
        #[cfg(target_os = "windows")]   return f.write_str("Windows");
        #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "android",
                      target_os = "linux", target_os = "windows")))]
        f.write_str("Unknown")
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Bitness {
    X64,
    X32,
}

impl fmt::Display for Bitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bitness::X64 => f.write_str("64-bit"),
            Bitness::X32 => f.write_str("32-bit"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Version;

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Unknown")
    }
}
