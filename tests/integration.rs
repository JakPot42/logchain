use std::fs;
use std::io::Write;

use logchain::hasher::{hash_bytes, to_hex};
use logchain::journal::{append_entry, ingest_file, load_state, read_entries, DataPaths};
use logchain::verify::{check_journal, is_clean};

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn paths(dir: &tempfile::TempDir) -> DataPaths {
    DataPaths::from_dir(dir.path())
}

// ── Full pipeline: ingest → verify clean ─────────────────────────────────────

#[test]
fn ingest_and_verify_clean() {
    let dir = tmp();
    let p = paths(&dir);

    // Write a sample log file.
    let log = dir.path().join("app.log");
    fs::write(
        &log,
        "2026-01-01T00:00:00Z INFO  service started\n\
         2026-01-01T00:01:00Z WARN  latency spike detected (p99=420ms)\n\
         2026-01-01T00:02:00Z ERROR database connection timeout\n\
         2026-01-01T00:03:00Z INFO  reconnected to database\n\
         2026-01-01T00:04:00Z INFO  health check passed\n",
    )
    .unwrap();

    let added = ingest_file(&log, &p.journal, &p.state).unwrap();
    assert_eq!(added, 5);

    let state = load_state(&p.state).unwrap();
    assert_eq!(state.entry_count, 5);
    assert!(state.merkle_root.is_some());

    assert!(is_clean(&p).unwrap(), "freshly ingested journal should be clean");
}

// ── Incremental ingest ────────────────────────────────────────────────────────

#[test]
fn incremental_ingest_stays_clean() {
    let dir = tmp();
    let p = paths(&dir);
    let log = dir.path().join("app.log");

    // First batch.
    fs::write(&log, "line1\nline2\nline3\n").unwrap();
    let added = ingest_file(&log, &p.journal, &p.state).unwrap();
    assert_eq!(added, 3);
    assert!(is_clean(&p).unwrap());

    // Second batch — append to the file.
    {
        let mut f = fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "line4").unwrap();
        writeln!(f, "line5").unwrap();
    }
    let added = ingest_file(&log, &p.journal, &p.state).unwrap();
    assert_eq!(added, 2);

    let state = load_state(&p.state).unwrap();
    assert_eq!(state.entry_count, 5);
    assert!(is_clean(&p).unwrap());
}

// ── Tamper: modify raw field → verify catches it ──────────────────────────────

#[test]
fn tamper_raw_field_is_caught() {
    let dir = tmp();
    let p = paths(&dir);

    for i in 0..6 {
        append_entry(&format!("log line {i}"), &p.journal, &p.state).unwrap();
    }
    assert!(is_clean(&p).unwrap());

    // Surgically modify the raw field of seq=3.
    let content = fs::read_to_string(&p.journal).unwrap();
    let tampered: String = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 3 {
                let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
                entry["raw"] = serde_json::Value::String("ATTACKER INJECTED THIS".to_string());
                serde_json::to_string(&entry).unwrap()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&p.journal, &tampered).unwrap();

    let result = check_journal(&p).unwrap();
    assert!(!result.clean, "verify must detect raw tampering");
    // Root is computed from stored hashes; modifying only raw leaves the root
    // intact. Tampering is caught at level 1 (raw → stored_hash mismatch).
    assert!(result.tampered_entries.iter().any(|t| matches!(t, logchain::verify::Tamper::RawModified { .. })));
}

// ── Tamper: modify hash field → verify catches it ────────────────────────────

#[test]
fn tamper_hash_field_is_caught() {
    let dir = tmp();
    let p = paths(&dir);

    for i in 0..4 {
        append_entry(&format!("entry {i}"), &p.journal, &p.state).unwrap();
    }
    assert!(is_clean(&p).unwrap());

    // Change hash field of seq=1 without touching raw.
    let content = fs::read_to_string(&p.journal).unwrap();
    let tampered: String = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 1 {
                let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
                entry["hash"] = serde_json::Value::String(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                );
                serde_json::to_string(&entry).unwrap()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&p.journal, &tampered).unwrap();

    let result = check_journal(&p).unwrap();
    assert!(!result.clean, "verify must detect hash-field tampering");
    assert!(!result.root_matches);
}

// ── Export snapshot has correct fields ───────────────────────────────────────

#[test]
fn export_snapshot_has_correct_count_and_root() {
    let dir = tmp();
    let p = paths(&dir);

    for i in 0..8 {
        append_entry(&format!("event {i}"), &p.journal, &p.state).unwrap();
    }

    let state = load_state(&p.state).unwrap();
    let entries = read_entries(&p.journal).unwrap();
    let snapshot = logchain::report::build_export(&state, &entries);

    assert_eq!(snapshot.entry_count, 8);
    assert_eq!(snapshot.entry_hashes.len(), 8);
    assert!(snapshot.merkle_root.is_some());
    assert_eq!(snapshot.merkle_root, state.merkle_root);
}

// ── Export hashes match independently recomputed values ──────────────────────

#[test]
fn export_hashes_match_raw_content() {
    let dir = tmp();
    let p = paths(&dir);

    let raw_lines = ["alpha", "beta", "gamma", "delta"];
    for line in &raw_lines {
        append_entry(line, &p.journal, &p.state).unwrap();
    }

    let state = load_state(&p.state).unwrap();
    let entries = read_entries(&p.journal).unwrap();
    let snapshot = logchain::report::build_export(&state, &entries);

    for (record, raw) in snapshot.entry_hashes.iter().zip(raw_lines.iter()) {
        let expected = to_hex(hash_bytes(raw.as_bytes()));
        assert_eq!(record.hash, expected, "hash mismatch for raw={raw}");
    }
}

// ── Merkle root changes when any entry changes ────────────────────────────────

#[test]
fn merkle_root_changes_after_tamper() {
    let dir = tmp();
    let p = paths(&dir);

    for i in 0..5 {
        append_entry(&format!("line {i}"), &p.journal, &p.state).unwrap();
    }
    let original_root = load_state(&p.state).unwrap().merkle_root.unwrap();

    // Tamper with entry 2.
    let content = fs::read_to_string(&p.journal).unwrap();
    let tampered: String = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 2 {
                let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
                entry["raw"] = serde_json::Value::String("tampered".to_string());
                // Also update the hash so level-1 doesn't immediately catch it —
                // only the Merkle root mismatch should fire.
                let new_hash = to_hex(hash_bytes(b"tampered"));
                entry["hash"] = serde_json::Value::String(new_hash);
                serde_json::to_string(&entry).unwrap()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&p.journal, &tampered).unwrap();

    // The state file still has the old root.
    let state = load_state(&p.state).unwrap();
    assert_eq!(state.merkle_root.unwrap(), original_root, "state root unchanged by journal edit");

    let result = check_journal(&p).unwrap();
    assert!(!result.clean);
    assert!(!result.root_matches);
    // Stored root ≠ recomputed root.
    assert_ne!(result.merkle_root_stored, result.merkle_root_recomputed);
}

// ── Empty journal is always clean ─────────────────────────────────────────────

#[test]
fn empty_journal_is_clean() {
    let dir = tmp();
    let p = paths(&dir);
    assert!(is_clean(&p).unwrap());
}

// ── Single entry round-trip ───────────────────────────────────────────────────

#[test]
fn single_entry_full_round_trip() {
    let dir = tmp();
    let p = paths(&dir);

    let raw = "2026-06-30T12:00:00Z INFO  system ready";
    let entry = append_entry(raw, &p.journal, &p.state).unwrap();

    assert_eq!(entry.seq, 0);
    assert_eq!(entry.raw, raw);
    assert_eq!(entry.hash, to_hex(hash_bytes(raw.as_bytes())));

    let state = load_state(&p.state).unwrap();
    assert_eq!(state.entry_count, 1);
    // For a single entry, the Merkle root IS the leaf hash (no pairing needed).
    assert_eq!(state.merkle_root, Some(entry.hash.clone()));

    assert!(is_clean(&p).unwrap());
}
