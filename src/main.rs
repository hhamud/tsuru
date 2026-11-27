#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use tsuru::format::KST_UTC_OFFSET_SECS;
use tsuru::{Config, process_pcap};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the PCAP file, or `-` to read from stdin
    #[arg(index = 1)]
    path: PathBuf,

    /// Reorder messages by quote accept time (3-second sliding window)
    #[arg(short = 'r', long = "reorder")]
    reorder: bool,

    /// UTC offset in seconds for packet arrival timestamps (default: +32400 / KST UTC+9)
    #[arg(long = "utc-offset-secs", default_value_t = KST_UTC_OFFSET_SECS, allow_hyphen_values = true)]
    utc_offset_secs: i64,
}

fn run(args: Args) -> Result<()> {
    let config = Config {
        reorder: args.reorder,
        utc_offset_secs: args.utc_offset_secs,
        ..Config::default()
    };

    let stdout = io::stdout();
    let out = stdout.lock();

    if args.path.as_os_str() == "-" {
        let stdin = io::stdin();
        process_pcap(stdin.lock(), out, config)
    } else {
        let file = File::open(&args.path)
            .with_context(|| format!("failed to open PCAP file: {}", args.path.display()))?;
        process_pcap(file, out, config)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match run(args) {
        Ok(()) => Ok(()),
        Err(err) => {
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::BrokenPipe)
            {
                return Ok(());
            }
            Err(err)
        }
    }
}
