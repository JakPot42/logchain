use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hasher::{from_hex, hash_bytes, to_hex, Hash};
use crate::merkle::compute_root;

#[derive(Error, Debug)]
pub enum JournalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bad hash hex in journal: {0}")]
    BadHex(#[from] hex::FromHexError),
    #[error("entry count mismatch: state says {state}, journal has {actual}")]
    CountMismatch { state: usize, actual: usize },
}

/// One persisted log entry.  Written as a single JSON object per line
/// (newline-delimited JSON / JSON Lines format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Zero-based sequential index — doubles as a tamper indicator:
    /// if any seq is missing or out of order, the journal was edited.
    pub seq: usize,
    /// RFC 3339 timestamp of when this entry was ingested (not the log's own timestamp).
    pub ingested_at: String,
    /// SHA-256 of `raw`, hex-encoded.  Stored alongside the text so that
    /// `verify` can detect raw-text tampering by recomputing and comparing.
    pub hash: String,
    /// The original log line, verbatim.
    pub raw: String,
}

/// Current aggregate state — stored in a separate file from the journal so
/// it can be compared independently (or archived out-of-band).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogchainState {
    /// Hex-encoded Merkle root over all `hash` fields in the journal, in order.
    /// `None` means no entries have been ingested yet.
    pub merkle_root: Option<String>,
    /// Number of entries in the journal.
    pub entry_count: usize,
    /// RFC 3339 timestamp of the last update.
    pub last_updated: String,
}

impl Default for LogchainState {
    fn default() -> Self {
        Self {
            merkle_root: None,
            entry_count: 0,
            last_updated: Utc::now().to_rfc3339(),
        }
    }
}

/// Resolved paths for the data directory.
pub struct DataPaths {
    pub journal: PathBuf,
    pub state: PathBuf,
}

impl DataPaths {
    pub fn from_dir(dir: &Path) -> Self {
        Self {
            journal: dir.join("logchain.journal"),
            state: dir.join("logchain.state"),
        }
    }
}

// ── State I/O ─────────────────────────────────────────────────────────────────

pub fn load_state(path: &Path) -> Result<LogchainState, JournalError> {
    if !path.exists() {
        return Ok(LogchainState::default());
    }
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn save_state(path: &Path, state: &LogchainState) -> Result<(), JournalError> {
    let text = serde_json::to_string_pretty(state)?;
    std::fs::write(path, text)?;
    Ok(())
}

// ── Journal I/O ───────────────────────────────────────────────────────────────

/// Append a single raw log line to the journal and update the state.
/// Idempotency note: callers are responsible for not feeding duplicate lines.
pub fn append_entry(
    raw: &str,
    journal_path: &Path,
    state_path: &Path,
) -> Result<JournalEntry, JournalError> {
    let state = load_state(state_path)?;
    let seq = state.entry_count;
    let entry_hash = hash_bytes(raw.as_bytes());

    let entry = JournalEntry {
        seq,
        ingested_at: Utc::now().to_rfc3339(),
        hash: to_hex(entry_hash),
        raw: raw.to_string(),
    };

    // Append the JSON line to the journal file.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)?;
    writeln!(file, "{}", serde_json::to_string(&entry)?)?;

    // Recompute Merkle root over all leaf hashes including the new one.
    let new_root = recompute_root_from_journal(journal_path)?;

    let new_state = LogchainState {
        merkle_root: new_root.map(to_hex),
        entry_count: seq + 1,
        last_updated: Utc::now().to_rfc3339(),
    };
    save_state(state_path, &new_state)?;

    Ok(entry)
}

/// Read all entries from the journal file.
pub fn read_entries(journal_path: &Path) -> Result<Vec<JournalEntry>, JournalError> {
    if !journal_path.exists() {
        return Ok(vec![]);
    }
    let file = File::open(journal_path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: JournalEntry = serde_json::from_str(&line)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Recompute the Merkle root from the current journal contents (not from state).
/// Called after every append to keep state in sync.
fn recompute_root_from_journal(journal_path: &Path) -> Result<Option<Hash>, JournalError> {
    let entries = read_entries(journal_path)?;
    if entries.is_empty() {
        return Ok(None);
    }
    // Decode every stored hash back to raw bytes for the Merkle computation.
    let leaf_hashes: Result<Vec<Hash>, _> = entries.iter().map(|e| from_hex(&e.hash)).collect();
    Ok(compute_root(&leaf_hashes?))
}

/// Collect the leaf hashes (decoded from hex) from a slice of entries.
pub fn leaf_hashes(entries: &[JournalEntry]) -> Result<Vec<Hash>, JournalError> {
    entries.iter().map(|e| from_hex(&e.hash).map_err(Into::into)).collect()
}

// ── Batch ingest from a log file ──────────────────────────────────────────────

/// Read a plain-text log file and append any lines not yet in the journal.
/// Returns the number of new entries added.
/// Skips blank lines.
pub fn ingest_file(
    log_path: &Path,
    journal_path: &Path,
    state_path: &Path,
) -> Result<usize, JournalError> {
    let state = load_state(state_path)?;
    let already_ingested = state.entry_count;

    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .filter_map(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    let mut added = 0;
    for line in lines.iter().skip(already_ingested) {
        append_entry(line, journal_path, state_path)?;
        added += 1;
    }
    Ok(added)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    pub fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn append_single_entry_and_read_back() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());

        append_entry("2026-01-01 INFO hello", &paths.journal, &paths.state).unwrap();

        let entries = read_entries(&paths.journal).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[0].raw, "2026-01-01 INFO hello");
    }

    #[test]
    fn multiple_entries_are_sequential() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());

        for i in 0..5 {
            append_entry(&format!("entry {i}"), &paths.journal, &paths.state).unwrap();
        }

        let entries = read_entries(&paths.journal).unwrap();
        assert_eq!(entries.len(), 5);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq, i);
        }
    }

    #[test]
    fn stored_hash_matches_raw_content() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());

        let raw = "2026-01-01 ERROR something went wrong";
        append_entry(raw, &paths.journal, &paths.state).unwrap();

        let entries = read_entries(&paths.journal).unwrap();
        let expected_hash = to_hex(hash_bytes(raw.as_bytes()));
        assert_eq!(entries[0].hash, expected_hash);
    }

    #[test]
    fn state_is_updated_after_append() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());

        assert_eq!(load_state(&paths.state).unwrap().entry_count, 0);

        append_entry("line one", &paths.journal, &paths.state).unwrap();
        append_entry("line two", &paths.journal, &paths.state).unwrap();

        let state = load_state(&paths.state).unwrap();
        assert_eq!(state.entry_count, 2);
        assert!(state.merkle_root.is_some());
    }

    #[test]
    fn state_round_trips_through_file() {
        let dir = tmp();
        let state_path = dir.path().join("test.state");

        let s = LogchainState {
            merkle_root: Some("deadbeef".to_string()),
            entry_count: 7,
            last_updated: "2026-01-01T00:00:00Z".to_string(),
        };
        save_state(&state_path, &s).unwrap();
        let loaded = load_state(&state_path).unwrap();

        assert_eq!(loaded.merkle_root, s.merkle_root);
        assert_eq!(loaded.entry_count, 7);
    }

    #[test]
    fn empty_journal_returns_no_entries() {
        let dir = tmp();
        let journal_path = dir.path().join("empty.journal");
        let entries = read_entries(&journal_path).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn ingest_file_skips_already_seen_lines() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());

        // Write a log file with 4 lines.
        let log_path = dir.path().join("app.log");
        fs::write(&log_path, "line1\nline2\nline3\nline4\n").unwrap();

        // First ingest: all 4 lines added.
        let added = ingest_file(&log_path, &paths.journal, &paths.state).unwrap();
        assert_eq!(added, 4);

        // Append a 5th line to the log file.
        let mut f = OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(f, "line5").unwrap();

        // Second ingest: only line5 is new.
        let added = ingest_file(&log_path, &paths.journal, &paths.state).unwrap();
        assert_eq!(added, 1);

        let entries = read_entries(&paths.journal).unwrap();
        assert_eq!(entries.len(), 5);
    }
}
