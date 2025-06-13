use std::time::{Duration, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use aya::{
    maps::{Array, MapData},
    Bpf,
};
use chrono::{DateTime, Local};

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SignalEvent {
    pub sender_pid: u32,
    pub sender_tgid: u32,
    pub target_pid: u32,
    pub target_tgid: u32,
    pub signal: u32,
    pub sender_comm: [u8; 16],
    pub target_comm: [u8; 16],
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub timestamp: u64,
    pub event_type: u8,
    pub exit_code: u32,
}

#[derive(Debug)]
pub enum Event {
    Signal(SignalEvent),
    Process(ProcessEvent),
}

pub struct SignalFilter {
    map: Array<MapData, u64>,
}

impl SignalFilter {
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        let map = Array::try_from(bpf.take_map("signal_filter").unwrap())?;
        Ok(Self { map })
    }

    pub fn allow_all(&mut self) -> Result<()> {
        for i in 0..64 {
            self.map.set(i, 1, 0)?;
        }
        Ok(())
    }

    pub fn allow_only(&mut self, signals: &[u32]) -> Result<()> {
        // First disable all
        for i in 0..64 {
            self.map.set(i, 0, 0)?;
        }
        // Then enable specified
        for &sig in signals {
            if sig < 64 {
                self.map.set(sig, 1, 0)?;
            }
        }
        Ok(())
    }
}

pub fn parse_signal(name: &str) -> Result<u32> {
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
            .map_err(|_| anyhow!("Unknown signal: {}", name)),
    }
}

pub struct SignalName;

impl SignalName {
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
}

fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&x| x == 0).unwrap_or(16);
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

fn timestamp_to_datetime(ts: u64) -> DateTime<Local> {
    let duration = Duration::from_nanos(ts);
    let system_time = UNIX_EPOCH + Duration::from_secs(duration.as_secs());
    DateTime::from(system_time)
}

pub fn parse_event(data: &[u8]) -> Result<Event> {
    if data.len() < std::mem::size_of::<SignalEvent>() {
        return Err(anyhow!("Data too small for event"));
    }

    // Try to determine event type by looking at the structure
    // Check if it looks like a process event (has event_type field)
    let potential_event_type = data[data.len() - 5]; // event_type position in ProcessEvent

    if potential_event_type <= 1 && data.len() == std::mem::size_of::<ProcessEvent>() {
        // Likely a process event
        let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ProcessEvent) };
        Ok(Event::Process(event))
    } else if data.len() == std::mem::size_of::<SignalEvent>() {
        // Likely a signal event
        let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const SignalEvent) };
        Ok(Event::Signal(event))
    } else {
        Err(anyhow!("Unknown event type"))
    }
}

pub fn format_signal_event(event: &SignalEvent) -> String {
    let time = timestamp_to_datetime(event.timestamp);
    let signal_name = SignalName::from_number(event.signal);
    let sender_comm = comm_to_string(&event.sender_comm);
    let target_comm = if event.target_comm[0] != 0 {
        comm_to_string(&event.target_comm)
    } else {
        "?".to_string()
    };

    format!(
        "[{}] SIGNAL: {} ({}) [{}/{}] -> [{}/{}] {} ({})",
        time.format("%H:%M:%S%.3f"),
        signal_name,
        event.signal,
        sender_comm,
        event.sender_pid,
        target_comm,
        event.target_pid,
        sender_comm,
        event.sender_tgid
    )
}

pub fn format_process_event(event: &ProcessEvent) -> String {
    let time = timestamp_to_datetime(event.timestamp);
    let comm = comm_to_string(&event.comm);

    match event.event_type {
        0 => format!(
            "[{}] FORK: {} (pid={}, tgid={}, ppid={})",
            time.format("%H:%M:%S%.3f"),
            comm,
            event.pid,
            event.tgid,
            event.ppid
        ),
        1 => format!(
            "[{}] EXIT: {} (pid={}, tgid={})",
            time.format("%H:%M:%S%.3f"),
            comm,
            event.pid,
            event.tgid
        ),
        _ => format!(
            "[{}] UNKNOWN: {} (pid={}, type={})",
            time.format("%H:%M:%S%.3f"),
            comm,
            event.pid,
            event.event_type
        ),
    }
}
