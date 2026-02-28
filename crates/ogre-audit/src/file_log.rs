use crate::entry::{AuditEntry, AuditFilter};
use crate::hash_chain::{compute_entry_hash, GENESIS_HASH};
use crate::{AuditError, AuditLog, ChainVerification};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// File-backed audit log. One JSON line per entry, append-only.
pub struct FileAuditLog {
    path: PathBuf,
    state: Mutex<LogState>,
}

struct LogState {
    last_hash: [u8; 32],
    next_sequence: u64,
}

impl FileAuditLog {
    /// Open or create an audit log file. Reads existing entries to recover state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();

        let (last_hash, next_sequence) = if path.exists() {
            Self::recover_state(&path)?
        } else {
            (GENESIS_HASH, 0)
        };

        Ok(Self {
            path,
            state: Mutex::new(LogState {
                last_hash,
                next_sequence,
            }),
        })
    }

    fn recover_state(path: &Path) -> Result<([u8; 32], u64), AuditError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_hash = GENESIS_HASH;
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)?;
            last_hash = entry.entry_hash;
            count = entry.sequence + 1;
        }

        Ok((last_hash, count))
    }

    fn read_all_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)?;
            entries.push(entry);
        }

        Ok(entries)
    }
}

impl AuditLog for FileAuditLog {
    fn append(&self, mut entry: AuditEntry) -> Result<(), AuditError> {
        let mut state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;

        entry.sequence = state.next_sequence;
        entry.previous_hash = state.last_hash;

        let entry_bytes = entry.hashable_bytes();
        entry.entry_hash = compute_entry_hash(entry.sequence, &entry_bytes, &entry.previous_hash);

        let json = serde_json::to_string(&entry)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{json}")?;

        state.last_hash = entry.entry_hash;
        state.next_sequence += 1;

        Ok(())
    }

    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>, AuditError> {
        let all = self.read_all_entries()?;
        let mut results: Vec<AuditEntry> = all.into_iter().filter(|e| e.matches(filter)).collect();

        if let Some(offset) = filter.offset {
            results = results.into_iter().skip(offset).collect();
        }
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    fn verify_chain(&self) -> Result<ChainVerification, AuditError> {
        let entries = self.read_all_entries()?;
        let mut previous_hash = GENESIS_HASH;
        let total = entries.len() as u64;

        for entry in &entries {
            if entry.previous_hash != previous_hash {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: entry.sequence,
                    first_broken: Some(entry.sequence),
                });
            }

            let entry_bytes = entry.hashable_bytes();
            let expected_hash =
                compute_entry_hash(entry.sequence, &entry_bytes, &entry.previous_hash);

            if entry.entry_hash != expected_hash {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: entry.sequence,
                    first_broken: Some(entry.sequence),
                });
            }

            previous_hash = entry.entry_hash;
        }

        Ok(ChainVerification {
            valid: true,
            entries_checked: total,
            first_broken: None,
        })
    }

    fn last_hash(&self) -> Result<[u8; 32], AuditError> {
        let state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state.last_hash)
    }

    fn len(&self) -> Result<u64, AuditError> {
        let state = self.state.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(state.next_sequence)
    }
}
