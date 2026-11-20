//! Windows-specific discovery primitives.
//!
//! On non-Windows targets every function reports
//! `CoreError::Platform("requires Windows")`. Other platforms come later
//! (see docs/roadmap.md).

#[cfg(windows)]
pub mod adapters;

#[cfg(windows)]
pub mod icmp;

#[cfg(windows)]
pub mod proxy;

#[cfg(windows)]
pub mod routes;


/// True when the running OS is supported by this platform crate.
pub fn supported() -> bool {
    cfg!(windows)
}
