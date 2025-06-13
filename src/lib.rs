//! RustSigWatch - A BPF-based system monitoring tool
//!
//! This library provides the core functionality for monitoring signals and process events
//! using BPF (Berkeley Packet Filter) programs in the Linux kernel.
//!
//! # Overview
//!
//! RustSigWatch hooks into kernel tracepoints to monitor:
//! - Signal delivery (kill, tkill, tgkill syscalls)
//! - Process creation (fork events)
//! - Process termination (exit events)
//!
//! # Example
//!
//! ```rust,no_run
//! use rustsigwatch::{SignalMonitor, SignalFilter};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut monitor = SignalMonitor::new()?;
//! monitor.start_monitoring(SignalFilter::default())?;
//! # Ok(())
//! # }
//! ```

pub mod bpf;
pub mod monitor;
pub mod signals;

pub use monitor::SignalMonitor;
pub use signals::{SignalFilter, SignalName};

/// Main error type for the library
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("BPF error: {0}")]
    Bpf(#[from] aya::BpfError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid signal: {0}")]
    InvalidSignal(String),
}

pub type Result<T> = std::result::Result<T, Error>;
