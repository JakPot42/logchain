use chrono::Utc;
use colored::Colorize;
use serde::Serialize;

use crate::journal::{JournalEntry, LogchainState};
use crate::verify::{Tamper, VerifyResult};

// ── Verify report ─────────────────────────────────────────────────────────────

pub fn print_verify_result(result: &VerifyResult) {
    println!();
    println!("{}", "═══ Logchain Integrity Verification ═══".bold());
    println!();

    // Entry count
    println!(
        "  {}  {}",
        "Entries checked:".dimmed(),
        result.entry_count.to_string().bold()
    );

    // Stored root
    match &result.merkle_root_stored {
        Some(r) => println!("  {}  {}", "Stored root:    ".dimmed(), r.dimmed()),
        None => println!("  {}  {}", "Stored root:    ".dimmed(), "(none)".dimmed()),
    }

    // Recomputed root
    match &result.merkle_root_recomputed {
        Some(r) => {
            let label = "Recomputed root:".dimmed();
            if result.root_matches {
                println!("  {label}  {}", r.green());
            } else {
                println!("  {label}  {}", r.red());
            }
        }
        None => println!("  {}  {}", "Recomputed root:".dimmed(), "(none)".dimmed()),
    }

    println!();

    // Root match status
    if result.root_matches {
        println!("  {} Merkle root matches", "✓".green().bold());
    } else {
        println!("  {} Merkle root MISMATCH — tree has been altered", "✗".red().bold());
    }

    // Per-entry issues
    if result.tampered_entries.is_empty() {
        println!("  {} All entry hashes valid", "✓".green().bold());
    } else {
        println!(
            "  {} {} tampered {}",
            "✗".red().bold(),
            result.tampered_entries.len().to_string().red().bold(),
            if result.tampered_entries.len() == 1 { "entry" } else { "entries" }
        );
        println!();

        for tamper in &result.tampered_entries {
            match tamper {
                Tamper::RawModified { seq, stored, recomputed } => {
                    println!(
                        "    {} seq={}: raw content modified",
                        "TAMPERED".red().bold(),
                        seq
                    );
                    println!("        stored hash:     {}", stored.dimmed());
                    println!("        recomputed hash: {}", recomputed.red());
                }
                Tamper::HashModified { seq } => {
                    println!(
                        "    {} seq={}: hash field modified directly (raw→hash consistent but Merkle root broken)",
                        "TAMPERED".red().bold(),
                        seq
                    );
                }
                Tamper::SeqMismatch { position, stored_seq } => {
                    println!(
                        "    {} position {}: seq field is {} (expected {})",
                        "TAMPERED".red().bold(),
                        position,
                        stored_seq.to_string().red(),
                        position.to_string().yellow()
                    );
                }
            }
        }
    }

    println!();

    // Final verdict
    if result.clean {
        println!("{}", "  ✓ INTEGRITY OK — no tampering detected".green().bold());
    } else {
        println!("{}", "  ✗ INTEGRITY VIOLATION — journal has been tampered with".red().bold());
    }

    println!();
}

// ── Export snapshot ───────────────────────────────────────────────────────────

/// A signed snapshot suitable for archival to an external system.
/// "Signed" here means cryptographically committed: the Merkle root is the
/// commitment over the full ordered log history.  Anyone holding the root can
/// verify any individual entry with an O(log n) Merkle proof.
#[derive(Debug, Serialize)]
pub struct ExportSnapshot {
    pub snapshot_version: &'static str,
    pub exported_at: String,
    pub entry_count: usize,
    pub merkle_root: Option<String>,
    /// The full ordered list of per-entry hashes.  With the root and this list,
    /// a verifier can reconstruct the tree and check any entry.
    pub entry_hashes: Vec<EntryHashRecord>,
}

#[derive(Debug, Serialize)]
pub struct EntryHashRecord {
    pub seq: usize,
    pub ingested_at: String,
    pub hash: String,
}

pub fn build_export(state: &LogchainState, entries: &[JournalEntry]) -> ExportSnapshot {
    ExportSnapshot {
        snapshot_version: "1",
        exported_at: Utc::now().to_rfc3339(),
        entry_count: state.entry_count,
        merkle_root: state.merkle_root.clone(),
        entry_hashes: entries
            .iter()
            .map(|e| EntryHashRecord {
                seq: e.seq,
                ingested_at: e.ingested_at.clone(),
                hash: e.hash.clone(),
            })
            .collect(),
    }
}

pub fn print_export(snapshot: &ExportSnapshot) {
    match serde_json::to_string_pretty(snapshot) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("export serialization error: {e}"),
    }
}

// ── Status summary ────────────────────────────────────────────────────────────

pub fn print_status(state: &LogchainState) {
    println!();
    println!("{}", "═══ Logchain Status ═══".bold());
    println!();
    println!("  {}  {}", "Entries:".dimmed(), state.entry_count.to_string().bold());
    match &state.merkle_root {
        Some(r) => println!("  {}  {}", "Merkle root:".dimmed(), r.green()),
        None => println!("  {}  {}", "Merkle root:".dimmed(), "(no entries yet)".dimmed()),
    }
    println!("  {}  {}", "Last updated:".dimmed(), state.last_updated.dimmed());
    println!();
}

// ── Ingestion progress ────────────────────────────────────────────────────────

pub fn print_ingested(entry: &JournalEntry) {
    println!(
        "  {} seq={} hash={}",
        "+".green().bold(),
        entry.seq.to_string().bold(),
        entry.hash[..16].dimmed()
    );
}

pub fn print_ingest_summary(added: usize, total: usize) {
    println!();
    if added == 0 {
        println!("{}", "  No new entries — log file is fully ingested.".dimmed());
    } else {
        println!(
            "  {}  {} new {} ingested ({} total)",
            "✓".green().bold(),
            added.to_string().bold(),
            if added == 1 { "entry" } else { "entries" },
            total
        );
    }
    println!();
}
