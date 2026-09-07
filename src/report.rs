use chrono::Utc;
use colored::Colorize;
use serde::Serialize;

use crate::hasher::{to_hex, Hash};
use crate::journal::{JournalEntry, LogchainState};
use crate::merkle::{compute_root, generate_proof, Side};
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
                Tamper::EntryHashMismatch { seq, stored, recomputed } => {
                    println!(
                        "    {} seq={}: raw content and stored hash disagree",
                        "TAMPERED".red().bold(),
                        seq
                    );
                    println!("        stored hash:     {}", stored.dimmed());
                    println!("        recomputed hash: {}", recomputed.red());
                    println!(
                        "        {}",
                        "(cannot tell which side was edited - the check is symmetric)".dimmed()
                    );
                }
                Tamper::RootMismatch => {
                    println!(
                        "    {} stored Merkle root does not match the journal",
                        "TAMPERED".red().bold(),
                    );
                    println!(
                        "        {}",
                        "(every entry is self-consistent, so entries were added, dropped or"
                            .dimmed()
                    );
                    println!(
                        "        {}",
                        " reordered, or the state file was edited - not attributable to one entry)"
                            .dimmed()
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

/// A committed snapshot suitable for archival to an external system.
///
/// NOT digitally signed.  There is no keypair and no signature anywhere in this
/// crate.  "Committed" means the Merkle root is a cryptographic commitment over
/// the full ordered log history: anyone holding the root can verify any
/// individual entry with an O(log n) Merkle proof, but nothing here attests to
/// WHO produced the snapshot.  Authenticating the producer requires a signature
/// scheme this crate does not implement.
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

// ── Inclusion proof ──────────────────────────────────────────────────────

/// A single Merkle inclusion proof, in the on-disk form documented in
/// `docs/FORMAT.md`.  Emitted so that a holder of the root can check one entry
/// without the journal, using any implementation of the format.
#[derive(Debug, Serialize)]
pub struct InclusionProofFile {
    pub proof_version: &'static str,
    pub seq: usize,
    pub entry_count: usize,
    pub leaf_hash: String,
    pub merkle_root: Option<String>,
    pub path: Vec<ProofStepRecord>,
}

/// One sibling on the path from the leaf to the root.  `side` says where the
/// SIBLING sits, which is what fixes the argument order at verification time.
#[derive(Debug, Serialize)]
pub struct ProofStepRecord {
    pub hash: String,
    pub side: &'static str,
}

/// Build the proof file for `seq`.  Returns `None` if `seq` is out of range.
pub fn build_inclusion_proof(
    seq: usize,
    entries: &[JournalEntry],
    leaves: &[Hash],
) -> Option<InclusionProofFile> {
    let nodes = generate_proof(leaves, seq)?;
    Some(InclusionProofFile {
        proof_version: "1",
        seq,
        entry_count: entries.len(),
        leaf_hash: to_hex(leaves[seq]),
        merkle_root: compute_root(leaves).map(to_hex),
        path: nodes
            .iter()
            .map(|n| ProofStepRecord {
                hash: to_hex(n.hash),
                side: match n.side {
                    Side::Left => "left",
                    Side::Right => "right",
                },
            })
            .collect(),
    })
}

pub fn print_inclusion_proof(proof: &InclusionProofFile) {
    match serde_json::to_string_pretty(proof) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("proof serialization error: {e}"),
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
