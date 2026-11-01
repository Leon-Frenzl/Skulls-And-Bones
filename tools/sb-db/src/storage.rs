use crate::entry::{Entry, EntryKind, HEADER_SIZE, MAGIC_BYTES};
use crate::index::{IndexDef, SecondaryIndexManager, ValueRecord};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub struct StorageEngine {
    pub path: PathBuf,
    pub file: File,
}

impl StorageEngine {
    /// Open or create an `.sbdb` single-file database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path_buf = path.as_ref().to_path_buf();
        if let Some(parent) = path_buf.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create DB directory: {}", e))?;
            }
        }

        let is_new =
            !path_buf.exists() || std::fs::metadata(&path_buf).map(|m| m.len()).unwrap_or(0) == 0;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path_buf)
            .map_err(|e| format!("Failed to open DB file '{}': {}", path_buf.display(), e))?;

        if is_new {
            Self::write_header(&mut file)?;
        }

        Ok(Self {
            path: path_buf,
            file,
        })
    }

    fn write_header(file: &mut File) -> Result<(), String> {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek error: {}", e))?;

        let mut hdr = [0u8; HEADER_SIZE];
        hdr[0..6].copy_from_slice(MAGIC_BYTES);
        hdr[6..8].copy_from_slice(&1u16.to_be_bytes()); // Version 1
        hdr[8..10].copy_from_slice(&0u16.to_be_bytes()); // Flags

        let now = chrono::Utc::now().timestamp_millis() as u64;
        hdr[10..18].copy_from_slice(&now.to_be_bytes());
        hdr[18..26].copy_from_slice(&0u64.to_be_bytes()); // Revision
                                                          // Remaining 6 bytes reserved

        file.write_all(&hdr)
            .map_err(|e| format!("Failed to write header: {}", e))?;
        file.flush()
            .map_err(|e| format!("Failed to flush header: {}", e))?;
        Ok(())
    }

    /// Append a single entry to disk
    pub fn append(&mut self, entry: &Entry) -> Result<(), String> {
        let bytes = entry.encode();
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| e.to_string())?;
        self.file.write_all(&bytes).map_err(|e| e.to_string())?;
        self.file.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Append a batch of entries atomically
    pub fn append_batch(&mut self, entries: &[Entry]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut total_bytes = Vec::new();
        for entry in entries {
            total_bytes.extend_from_slice(&entry.encode());
        }

        self.file
            .seek(SeekFrom::End(0))
            .map_err(|e| e.to_string())?;
        self.file
            .write_all(&total_bytes)
            .map_err(|e| e.to_string())?;
        self.file.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Replay entries from disk, recover state, and truncate any corrupted tail
    pub fn recover(
        &mut self,
    ) -> Result<(BTreeMap<String, ValueRecord>, SecondaryIndexManager, u64), String> {
        let mut index = BTreeMap::new();
        let mut secondary = SecondaryIndexManager::new();
        let mut max_tx_id = 0u64;

        let file_len = self.file.metadata().map_err(|e| e.to_string())?.len();
        if file_len < HEADER_SIZE as u64 {
            Self::write_header(&mut self.file)?;
            return Ok((index, secondary, 0));
        }

        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut magic_buf = [0u8; 6];
        self.file
            .read_exact(&mut magic_buf)
            .map_err(|e| e.to_string())?;
        if &magic_buf != MAGIC_BYTES {
            return Err("Invalid file header: magic bytes mismatch".into());
        }

        // Seek past header
        self.file
            .seek(SeekFrom::Start(HEADER_SIZE as u64))
            .map_err(|e| e.to_string())?;

        let mut last_valid_offset = HEADER_SIZE as u64;

        loop {
            let current_offset = match self.file.stream_position() {
                Ok(pos) => pos,
                Err(_) => break,
            };

            if current_offset >= file_len {
                break;
            }

            match Entry::decode(&mut self.file) {
                Ok(entry) => {
                    last_valid_offset = self.file.stream_position().unwrap_or(current_offset);
                    if entry.tx_id > max_tx_id {
                        max_tx_id = entry.tx_id;
                    }

                    match entry.kind {
                        EntryKind::Set => {
                            let old_doc = index.get(&entry.key).map(|r| &r.value);
                            secondary.on_set(&entry.key, &entry.value, old_doc);

                            index.insert(
                                entry.key,
                                ValueRecord {
                                    value: entry.value,
                                    expires_at: entry.ttl_expires_at,
                                    revision: entry.tx_id,
                                    updated_at: entry.timestamp,
                                },
                            );
                        }
                        EntryKind::Delete => {
                            if let Some(old_record) = index.remove(&entry.key) {
                                secondary.on_delete(&entry.key, &old_record.value);
                            }
                        }
                        EntryKind::CreateIndex => {
                            let field = entry.value.as_str().unwrap_or("").to_string();
                            secondary.register_index(entry.key.clone(), field);
                            for (k, v) in &index {
                                if k.starts_with(&entry.key) {
                                    secondary.on_set(k, &v.value, None);
                                }
                            }
                        }
                        EntryKind::DropIndex => {
                            secondary.drop_index(&entry.key, entry.value.as_str().unwrap_or(""));
                        }
                        EntryKind::TxBegin | EntryKind::TxCommit => {}
                    }
                }
                Err(_) => {
                    // Corruption or partial write at tail: truncate file to last clean entry
                    eprintln!(
                        "\x1b[33m[!] Partial or corrupt entry at offset {}. Safely truncating to {}.\x1b[0m",
                        current_offset, last_valid_offset
                    );
                    let _ = self.file.set_len(last_valid_offset);
                    break;
                }
            }
        }

        Ok((index, secondary, max_tx_id))
    }

    /// Compact database file by rewriting live records to a new atomic file
    pub fn compact(
        &mut self,
        active_records: &BTreeMap<String, ValueRecord>,
        indexes: &[IndexDef],
    ) -> Result<u64, String> {
        let temp_path = self.path.with_extension("sbdb.tmp");
        let old_size = self.file.metadata().map(|m| m.len()).unwrap_or(0);

        let mut temp_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|e| format!("Failed to create compaction tmp file: {}", e))?;

        Self::write_header(&mut temp_file)?;

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut tx_id = 1u64;

        // Write index definitions first
        for def in indexes {
            let entry = Entry {
                kind: EntryKind::CreateIndex,
                tx_id,
                timestamp: now,
                ttl_expires_at: 0,
                key: def.prefix.clone(),
                value: serde_json::Value::String(def.field.clone()),
            };
            temp_file
                .write_all(&entry.encode())
                .map_err(|e| e.to_string())?;
            tx_id += 1;
        }

        // Write live, unexpired records
        for (key, record) in active_records {
            if record.is_expired(now) {
                continue;
            }

            let entry = Entry {
                kind: EntryKind::Set,
                tx_id,
                timestamp: record.updated_at,
                ttl_expires_at: record.expires_at,
                key: key.clone(),
                value: record.value.clone(),
            };
            temp_file
                .write_all(&entry.encode())
                .map_err(|e| e.to_string())?;
            tx_id += 1;
        }

        temp_file.flush().map_err(|e| e.to_string())?;
        drop(temp_file);

        // Replace original file atomically
        std::fs::rename(&temp_path, &self.path)
            .map_err(|e| format!("Atomic rename failed: {}", e))?;

        // Re-open original file handle
        self.file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(|e| format!("Failed to reopen compacted file: {}", e))?;

        let new_size = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        let reclaimed = old_size.saturating_sub(new_size);
        Ok(reclaimed)
    }
}
