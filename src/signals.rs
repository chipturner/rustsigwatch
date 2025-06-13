//! Signal-related types and utilities
//!
//! This module contains signal parsing, filtering, and formatting functionality.

use crate::{Error, Result};

/// Signal filter configuration
#[derive(Debug, Clone)]
pub struct SignalFilter {
    /// Signals to monitor (empty = monitor all)
    pub signals: Vec<u32>,
    /// Whether to monitor all signals
    pub all_signals: bool,
}

impl Default for SignalFilter {
    fn default() -> Self {
        Self {
            signals: vec![15], // SIGTERM by default
            all_signals: false,
        }
    }
}

impl SignalFilter {
    /// Create a filter for specific signals
    pub fn for_signals(signals: Vec<u32>) -> Self {
        Self {
            signals,
            all_signals: false,
        }
    }

    /// Create a filter that monitors all signals
    pub fn all() -> Self {
        Self {
            signals: Vec::new(),
            all_signals: true,
        }
    }

    /// Check if a signal should be monitored
    pub fn should_monitor(&self, signal: u32) -> bool {
        if self.all_signals {
            true
        } else {
            self.signals.contains(&signal)
        }
    }
}

/// Signal name resolution
pub struct SignalName;

impl SignalName {
    /// Convert signal number to name
    pub fn from_number(sig: u32) -> &'static str {
        match sig {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            4 => "SIGILL",
            5 => "SIGTRAP",
            6 => "SIGABRT",
            7 => "SIGBUS",
            8 => "SIGFPE",
            9 => "SIGKILL",
            10 => "SIGUSR1",
            11 => "SIGSEGV",
            12 => "SIGUSR2",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            16 => "SIGSTKFLT",
            17 => "SIGCHLD",
            18 => "SIGCONT",
            19 => "SIGSTOP",
            20 => "SIGTSTP",
            21 => "SIGTTIN",
            22 => "SIGTTOU",
            23 => "SIGURG",
            24 => "SIGXCPU",
            25 => "SIGXFSZ",
            26 => "SIGVTALRM",
            27 => "SIGPROF",
            28 => "SIGWINCH",
            29 => "SIGIO",
            30 => "SIGPWR",
            31 => "SIGSYS",
            _ => "UNKNOWN",
        }
    }

    /// Parse signal name to number
    pub fn parse(name: &str) -> Result<u32> {
        match name.to_uppercase().as_str() {
            "SIGHUP" | "HUP" => Ok(1),
            "SIGINT" | "INT" => Ok(2),
            "SIGQUIT" | "QUIT" => Ok(3),
            "SIGILL" | "ILL" => Ok(4),
            "SIGTRAP" | "TRAP" => Ok(5),
            "SIGABRT" | "ABRT" => Ok(6),
            "SIGBUS" | "BUS" => Ok(7),
            "SIGFPE" | "FPE" => Ok(8),
            "SIGKILL" | "KILL" => Ok(9),
            "SIGUSR1" | "USR1" => Ok(10),
            "SIGSEGV" | "SEGV" => Ok(11),
            "SIGUSR2" | "USR2" => Ok(12),
            "SIGPIPE" | "PIPE" => Ok(13),
            "SIGALRM" | "ALRM" => Ok(14),
            "SIGTERM" | "TERM" => Ok(15),
            "SIGSTKFLT" | "STKFLT" => Ok(16),
            "SIGCHLD" | "CHLD" => Ok(17),
            "SIGCONT" | "CONT" => Ok(18),
            "SIGSTOP" | "STOP" => Ok(19),
            "SIGTSTP" | "TSTP" => Ok(20),
            "SIGTTIN" | "TTIN" => Ok(21),
            "SIGTTOU" | "TTOU" => Ok(22),
            "SIGURG" | "URG" => Ok(23),
            "SIGXCPU" | "XCPU" => Ok(24),
            "SIGXFSZ" | "XFSZ" => Ok(25),
            "SIGVTALRM" | "VTALRM" => Ok(26),
            "SIGPROF" | "PROF" => Ok(27),
            "SIGWINCH" | "WINCH" => Ok(28),
            "SIGIO" | "IO" => Ok(29),
            "SIGPWR" | "PWR" => Ok(30),
            "SIGSYS" | "SYS" => Ok(31),
            _ => name
                .parse::<u32>()
                .map_err(|_| Error::InvalidSignal(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_parsing() {
        assert_eq!(SignalName::parse("SIGTERM").unwrap(), 15);
        assert_eq!(SignalName::parse("TERM").unwrap(), 15);
        assert_eq!(SignalName::parse("15").unwrap(), 15);
        assert!(SignalName::parse("INVALID").is_err());
    }

    #[test]
    fn test_signal_names() {
        assert_eq!(SignalName::from_number(15), "SIGTERM");
        assert_eq!(SignalName::from_number(9), "SIGKILL");
        assert_eq!(SignalName::from_number(999), "UNKNOWN");
    }

    #[test]
    fn test_signal_filter() {
        let filter = SignalFilter::for_signals(vec![15, 9]);
        assert!(filter.should_monitor(15));
        assert!(filter.should_monitor(9));
        assert!(!filter.should_monitor(2));

        let all_filter = SignalFilter::all();
        assert!(all_filter.should_monitor(15));
        assert!(all_filter.should_monitor(2));
    }
}
