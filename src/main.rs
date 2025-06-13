use std::convert::TryFrom;

use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, util::online_cpus, Bpf};
// use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

mod bpf;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "SIGTERM")]
    signals: Vec<String>,

    #[clap(short, long)]
    all_signals: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sigwatch.bpf.o"
    )))?;

    // Skip eBPF logger for now due to version mismatch
    // if let Err(e) = EbpfLogger::init(&mut bpf) {
    //     warn!("failed to initialize eBPF logger: {}", e);
    // }

    // Configure signal filter
    let mut signal_filter = bpf::SignalFilter::new(&mut bpf)?;
    if opt.all_signals {
        signal_filter.allow_all()?;
    } else {
        let signals: Vec<u32> = opt
            .signals
            .iter()
            .map(|s| bpf::parse_signal(s))
            .collect::<Result<Vec<_>>>()?;
        signal_filter.allow_only(&signals)?;
    }

    // Attach programs
    let program: &mut TracePoint = bpf
        .program_mut("trace_kill")
        .context("failed to get trace_kill program")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_kill")?;

    let program: &mut TracePoint = bpf
        .program_mut("trace_tkill")
        .context("failed to get trace_tkill program")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_tkill")?;

    let program: &mut TracePoint = bpf
        .program_mut("trace_tgkill")
        .context("failed to get trace_tgkill program")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_tgkill")?;

    let program: &mut TracePoint = bpf
        .program_mut("trace_fork")
        .context("failed to get trace_fork program")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;

    let program: &mut TracePoint = bpf
        .program_mut("trace_exit")
        .context("failed to get trace_exit program")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exit")?;

    info!(
        "SigWatch started. Monitoring signals: {:?}",
        if opt.all_signals {
            vec!["ALL".to_string()]
        } else {
            opt.signals
        }
    );

    // Process events
    let cpus = online_cpus()?;
    let mut ring_buf = RingBuf::try_from(bpf.take_map("events").unwrap())?;

    let _buffers = vec![BytesMut::with_capacity(8192); cpus.len()];

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = async {
                match ring_buf.next() {
                    Some(item) => {
                        let data = item.as_ref();
                        if data.len() >= 8 {
                            // Check discriminator to determine event type
                            match bpf::parse_event(data) {
                                Ok(event) => match event {
                                    bpf::Event::Signal(sig_event) => {
                                        println!("{}", bpf::format_signal_event(&sig_event));
                                    }
                                    bpf::Event::Process(proc_event) => {
                                        println!("{}", bpf::format_process_event(&proc_event));
                                    }
                                },
                                Err(e) => {
                                    warn!("Failed to parse event: {}", e);
                                }
                            }
                        }
                    }
                    None => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            } => {}
        }
    }

    Ok(())
}
