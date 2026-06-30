use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};

use logchain::journal::{append_entry, ingest_file, load_state, read_entries, DataPaths};
use logchain::report::{
    build_export, print_export, print_ingest_summary, print_ingested, print_status,
    print_verify_result,
};
use logchain::verify::check_journal;

#[derive(Parser)]
#[command(name = "logchain", about = "Tamper-evident log aggregator with Merkle integrity")]
struct Cli {
    /// Directory where the journal and state files are stored.
    #[arg(long, default_value = "./logchain-data")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Tail a log file, ingesting new lines as they arrive.
    Tail {
        /// Path to the log file to monitor.
        file: PathBuf,

        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,

        /// Read the entire file once and exit (no live polling).
        #[arg(long)]
        once: bool,
    },

    /// Verify the integrity of the entire journal against the stored Merkle root.
    Verify,

    /// Export a signed Merkle snapshot for archival (JSON to stdout).
    Export,

    /// Show the current journal status (entry count, Merkle root, last updated).
    Status,
}

fn main() {
    let cli = Cli::parse();

    // Ensure the data directory exists.
    if let Err(e) = fs::create_dir_all(&cli.data_dir) {
        eprintln!("error: cannot create data directory {}: {e}", cli.data_dir.display());
        std::process::exit(1);
    }

    let paths = DataPaths::from_dir(&cli.data_dir);

    match cli.command {
        Command::Tail { file, interval_ms, once } => {
            cmd_tail(&file, &paths, interval_ms, once);
        }
        Command::Verify => {
            cmd_verify(&paths);
        }
        Command::Export => {
            cmd_export(&paths);
        }
        Command::Status => {
            cmd_status(&paths);
        }
    }
}

// ── tail ─────────────────────────────────────────────────────────────────────

fn cmd_tail(log_path: &PathBuf, paths: &DataPaths, interval_ms: u64, once: bool) {
    if !log_path.exists() {
        eprintln!("error: file not found: {}", log_path.display());
        std::process::exit(1);
    }

    if once {
        println!("Ingesting {} ...", log_path.display());
        match ingest_file(log_path, &paths.journal, &paths.state) {
            Ok(added) => {
                let state = load_state(&paths.state).unwrap_or_default();
                print_ingest_summary(added, state.entry_count);
            }
            Err(e) => {
                eprintln!("error during ingestion: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Live tail mode: catch up on existing content, then poll.
    println!("Tailing {} (Ctrl-C to stop)", log_path.display());
    println!();

    let already = load_state(&paths.state).unwrap_or_default().entry_count;

    let file = match fs::File::open(log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error opening file: {e}");
            std::process::exit(1);
        }
    };
    let mut reader = BufReader::new(file);

    // Skip lines already ingested in a previous session.
    let mut line = String::new();
    for _ in 0..already {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
    }

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(interval_ms));
            }
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\n', '\r']);
                if trimmed.is_empty() {
                    continue;
                }
                match append_entry(trimmed, &paths.journal, &paths.state) {
                    Ok(entry) => print_ingested(&entry),
                    Err(e) => eprintln!("  error ingesting line: {e}"),
                }
            }
            Err(e) => {
                eprintln!("  read error: {e}");
                thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    }
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(paths: &DataPaths) {
    match check_journal(paths) {
        Ok(result) => {
            print_verify_result(&result);
            if !result.clean {
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("error reading journal: {e}");
            std::process::exit(1);
        }
    }
}

// ── export ────────────────────────────────────────────────────────────────────

fn cmd_export(paths: &DataPaths) {
    let state = match load_state(&paths.state) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error reading state: {e}");
            std::process::exit(1);
        }
    };

    let entries = match read_entries(&paths.journal) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error reading journal: {e}");
            std::process::exit(1);
        }
    };

    let snapshot = build_export(&state, &entries);
    print_export(&snapshot);
}

// ── status ────────────────────────────────────────────────────────────────────

fn cmd_status(paths: &DataPaths) {
    match load_state(&paths.state) {
        Ok(state) => print_status(&state),
        Err(e) => {
            eprintln!("error reading state: {e}");
            std::process::exit(1);
        }
    }
}
