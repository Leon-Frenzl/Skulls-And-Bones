use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique identifier for an element in the sequence CRDT (Logoot / LSeq inspired).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionId {
    pub pos: Vec<u32>,
    pub peer: String,
    pub clock: u64,
}

impl PartialOrd for PositionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PositionId {
    fn cmp(&self, other: &Self) -> Ordering {
        let min_len = self.pos.len().min(other.pos.len());
        for i in 0..min_len {
            if self.pos[i] != other.pos[i] {
                return self.pos[i].cmp(&other.pos[i]);
            }
        }
        if self.pos.len() != other.pos.len() {
            return self.pos.len().cmp(&other.pos.len());
        }
        match self.clock.cmp(&other.clock) {
            Ordering::Equal => self.peer.cmp(&other.peer),
            ord => ord,
        }
    }
}

/// A character or token with its unique CRDT position identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrdtChar {
    pub id: PositionId,
    pub ch: char,
    pub visible: bool,
}

/// A soft lock on an AST or line range to prevent conflicting formatters from kicking in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftLock {
    pub start_line: usize,
    pub end_line: usize,
    pub locked_by: String,
    pub expires_at: i64,
}

/// An atomic operation broadcast across the Swarm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CrdtOp {
    Insert { id: PositionId, ch: char },
    Delete { id: PositionId },
    Lock { lock: SoftLock },
    Unlock { locked_by: String },
}

/// Live cursor position of a remote peer in a specific file buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCursor {
    pub peer: String,
    pub file_path: String,
    pub line: usize,
    pub col: usize,
    pub color: String,
    pub updated_at: u64,
}

/// Helper to assign deterministic aesthetic colors to peers
pub fn peer_to_color(peer: &str) -> &'static str {
    let colors = [
        "#38bdf8", // Sky 400
        "#a855f7", // Purple 500
        "#34d399", // Emerald 400
        "#f59e0b", // Amber 500
        "#f43f5e", // Rose 500
        "#818cf8", // Indigo 400
        "#06b6d4", // Cyan 500
        "#ec4899", // Pink 500
    ];
    let sum: usize = peer.bytes().map(|b| b as usize).sum();
    colors[sum % colors.len()]
}

/// In-memory registry tracking live peer cursor locations across workspace files.
#[derive(Clone, Debug, Default)]
pub struct PeerCursorRegistry {
    cursors: HashMap<(String, String), PeerCursor>, // (file_path, peer) -> PeerCursor
}

impl PeerCursorRegistry {
    pub fn new() -> Self {
        Self {
            cursors: HashMap::new(),
        }
    }

    pub fn update_cursor(
        &mut self,
        peer: &str,
        file_path: &str,
        line: usize,
        col: usize,
    ) -> PeerCursor {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let color = peer_to_color(peer).to_string();
        let cursor = PeerCursor {
            peer: peer.to_string(),
            file_path: file_path.to_string(),
            line,
            col,
            color,
            updated_at: now,
        };

        self.cursors
            .insert((file_path.to_string(), peer.to_string()), cursor.clone());
        cursor
    }

    pub fn get_active_cursors(&self, file_path: &str, max_age_ms: u64) -> Vec<PeerCursor> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        self.cursors
            .iter()
            .filter(|((path, _), c)| {
                path == file_path && (now.saturating_sub(c.updated_at) <= max_age_ms)
            })
            .map(|(_, c)| c.clone())
            .collect()
    }

    pub fn remove_peer(&mut self, peer: &str) {
        self.cursors.retain(|(_, p), _| p != peer);
    }
}

/// Replicated text buffer managing conflict-free text editing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrdtBuffer {
    pub chars: Vec<CrdtChar>,
    pub locks: Vec<SoftLock>,
    pub lamport_clock: u64,
}

impl CrdtBuffer {
    pub fn new() -> Self {
        Self {
            chars: Vec::new(),
            locks: Vec::new(),
            lamport_clock: 0,
        }
    }

    pub fn from_str(text: &str, peer: &str) -> Self {
        let mut buffer = Self::new();
        let step = 100u32;
        let mut current_pos = step;

        for ch in text.chars() {
            buffer.lamport_clock += 1;
            let id = PositionId {
                pos: vec![current_pos],
                peer: peer.to_string(),
                clock: buffer.lamport_clock,
            };
            buffer.chars.push(CrdtChar {
                id,
                ch,
                visible: true,
            });
            current_pos += step;
        }

        buffer
    }

    pub fn to_string(&self) -> String {
        self.chars
            .iter()
            .filter(|c| c.visible)
            .map(|c| c.ch)
            .collect()
    }

    pub fn visible_len(&self) -> usize {
        self.chars.iter().filter(|c| c.visible).count()
    }

    fn generate_position_between(
        &self,
        left_idx: Option<usize>,
        right_idx: Option<usize>,
        peer: &str,
    ) -> PositionId {
        let left_pos = left_idx
            .and_then(|idx| self.chars.iter().filter(|c| c.visible).nth(idx))
            .map(|c| c.id.pos.clone());

        let right_pos = right_idx
            .and_then(|idx| self.chars.iter().filter(|c| c.visible).nth(idx))
            .map(|c| c.id.pos.clone());

        let pos = match (left_pos, right_pos) {
            (None, None) => vec![100],
            (None, Some(right)) => {
                let first = right.first().copied().unwrap_or(100);
                if first > 1 {
                    vec![first / 2]
                } else {
                    let mut p = right.clone();
                    p.push(50);
                    p
                }
            }
            (Some(left), None) => {
                let mut p = left.clone();
                let last = p.last_mut().unwrap();
                *last += 100;
                p
            }
            (Some(left), Some(right)) => {
                let mut res = Vec::new();
                let mut diff_found = false;

                for i in 0..left.len().max(right.len()) {
                    let l_val = left.get(i).copied().unwrap_or(0);
                    let r_val = right.get(i).copied().unwrap_or(0);

                    if l_val == r_val && !diff_found {
                        res.push(l_val);
                    } else if !diff_found {
                        if r_val > l_val + 1 {
                            res.push((l_val + r_val) / 2);
                            diff_found = true;
                            break;
                        } else {
                            res.push(l_val);
                            diff_found = true;
                        }
                    } else {
                        res.push(50);
                        break;
                    }
                }

                if !diff_found {
                    res.push(50);
                }
                res
            }
        };

        PositionId {
            pos,
            peer: peer.to_string(),
            clock: self.lamport_clock + 1,
        }
    }

    pub fn local_insert(&mut self, index: usize, ch: char, peer: &str) -> CrdtOp {
        self.lamport_clock += 1;
        let left_idx = if index > 0 { Some(index - 1) } else { None };
        let right_idx = if index < self.visible_len() {
            Some(index)
        } else {
            None
        };
        let id = self.generate_position_between(left_idx, right_idx, peer);

        let crdt_char = CrdtChar {
            id: id.clone(),
            ch,
            visible: true,
        };

        let insert_idx = self
            .chars
            .binary_search_by(|c| c.id.cmp(&crdt_char.id))
            .unwrap_or_else(|idx| idx);

        self.chars.insert(insert_idx, crdt_char);
        CrdtOp::Insert { id, ch }
    }

    /// Batch insert of a string chunk starting at a given index
    pub fn local_insert_str(&mut self, mut index: usize, text: &str, peer: &str) -> Vec<CrdtOp> {
        let mut ops = Vec::with_capacity(text.len());
        for ch in text.chars() {
            let op = self.local_insert(index, ch, peer);
            ops.push(op);
            index += 1;
        }
        ops
    }

    pub fn local_delete(&mut self, index: usize) -> Option<CrdtOp> {
        self.lamport_clock += 1;
        let mut current_visible = 0;
        for item in self.chars.iter_mut() {
            if item.visible {
                if current_visible == index {
                    item.visible = false;
                    return Some(CrdtOp::Delete {
                        id: item.id.clone(),
                    });
                }
                current_visible += 1;
            }
        }
        None
    }

    /// Batch delete of a character count range starting at start_index
    pub fn local_delete_range(&mut self, start_index: usize, count: usize) -> Vec<CrdtOp> {
        let mut ops = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(op) = self.local_delete(start_index) {
                ops.push(op);
            } else {
                break;
            }
        }
        ops
    }

    pub fn apply_remote_op(&mut self, op: CrdtOp) {
        match op {
            CrdtOp::Insert { id, ch } => {
                if id.clock > self.lamport_clock {
                    self.lamport_clock = id.clock;
                }
                match self.chars.binary_search_by(|c| c.id.cmp(&id)) {
                    Ok(idx) => {
                        self.chars[idx].visible = true;
                        self.chars[idx].ch = ch;
                    }
                    Err(idx) => {
                        self.chars.insert(
                            idx,
                            CrdtChar {
                                id,
                                ch,
                                visible: true,
                            },
                        );
                    }
                }
            }
            CrdtOp::Delete { id } => {
                if id.clock > self.lamport_clock {
                    self.lamport_clock = id.clock;
                }
                if let Ok(idx) = self.chars.binary_search_by(|c| c.id.cmp(&id)) {
                    self.chars[idx].visible = false;
                }
            }
            CrdtOp::Lock { lock } => {
                self.locks.retain(|l| l.locked_by != lock.locked_by);
                self.locks.push(lock);
            }
            CrdtOp::Unlock { locked_by } => {
                self.locks.retain(|l| l.locked_by != locked_by);
            }
        }
    }

    pub fn apply_remote_ops(&mut self, ops: &[CrdtOp]) {
        for op in ops {
            self.apply_remote_op(op.clone());
        }
    }
}

/// Global session manager managing active CRDT buffers per file in memory
/// alongside connected peer cursors.
#[derive(Clone, Debug, Default)]
pub struct CrdtSessionManager {
    buffers: Arc<RwLock<HashMap<String, CrdtBuffer>>>,
    cursors: Arc<RwLock<PeerCursorRegistry>>,
}

impl CrdtSessionManager {
    pub fn new() -> Self {
        Self {
            buffers: Arc::new(RwLock::new(HashMap::new())),
            cursors: Arc::new(RwLock::new(PeerCursorRegistry::new())),
        }
    }

    /// Initializes or retrieves an active CRDT buffer for the given file path.
    pub fn get_or_init_buffer(&self, file_path: &str, initial_content: &str, peer: &str) -> String {
        let mut bufs = self.buffers.write().unwrap();
        if let Some(buf) = bufs.get(file_path) {
            buf.to_string()
        } else {
            let buf = CrdtBuffer::from_str(initial_content, peer);
            let s = buf.to_string();
            bufs.insert(file_path.to_string(), buf);
            s
        }
    }

    /// Reset or replace buffer content directly (e.g. after file reload or save)
    pub fn reset_buffer(&self, file_path: &str, content: &str, peer: &str) {
        let mut bufs = self.buffers.write().unwrap();
        bufs.insert(file_path.to_string(), CrdtBuffer::from_str(content, peer));
    }

    /// Applies a local edit change (replacement of delete_len characters at start_offset with insert_text)
    pub fn apply_local_change(
        &self,
        file_path: &str,
        start_offset: usize,
        delete_len: usize,
        insert_text: &str,
        peer: &str,
    ) -> Result<Vec<CrdtOp>, String> {
        let mut bufs = self.buffers.write().unwrap();
        let buf = bufs
            .get_mut(file_path)
            .ok_or_else(|| format!("CRDT buffer for '{}' not initialized", file_path))?;

        let mut ops = Vec::new();

        if delete_len > 0 {
            let del_ops = buf.local_delete_range(start_offset, delete_len);
            ops.extend(del_ops);
        }

        if !insert_text.is_empty() {
            let ins_ops = buf.local_insert_str(start_offset, insert_text, peer);
            ops.extend(ins_ops);
        }

        Ok(ops)
    }

    /// Applies remote CRDT operations into the file buffer and returns the resulting full text
    pub fn apply_remote_ops(&self, file_path: &str, ops: &[CrdtOp]) -> Result<String, String> {
        let mut bufs = self.buffers.write().unwrap();
        let buf = bufs
            .get_mut(file_path)
            .ok_or_else(|| format!("CRDT buffer for '{}' not initialized", file_path))?;

        buf.apply_remote_ops(ops);
        Ok(buf.to_string())
    }

    /// Reads current string content of the buffer
    pub fn get_content(&self, file_path: &str) -> Option<String> {
        let bufs = self.buffers.read().unwrap();
        bufs.get(file_path).map(|b| b.to_string())
    }

    /// Updates peer cursor coordinates
    pub fn update_cursor(
        &self,
        peer: &str,
        file_path: &str,
        line: usize,
        col: usize,
    ) -> PeerCursor {
        let mut reg = self.cursors.write().unwrap();
        reg.update_cursor(peer, file_path, line, col)
    }

    /// Returns active peer cursors in this file (last seen within 15 seconds)
    pub fn get_active_cursors(&self, file_path: &str) -> Vec<PeerCursor> {
        let reg = self.cursors.read().unwrap();
        reg.get_active_cursors(file_path, 15_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crdt_basic_flow() {
        let mut buf = CrdtBuffer::new();
        buf.local_insert(0, 'A', "peer-1");
        buf.local_insert(1, 'B', "peer-1");
        assert_eq!(buf.to_string(), "AB");
    }

    #[test]
    fn test_crdt_batch_insert_and_delete() {
        let mut buf = CrdtBuffer::from_str("Hello World", "peer-alice");
        assert_eq!(buf.to_string(), "Hello World");

        // Delete " World" (index 5, 6 chars)
        let del_ops = buf.local_delete_range(5, 6);
        assert_eq!(del_ops.len(), 6);
        assert_eq!(buf.to_string(), "Hello");

        // Insert " Skulls" at index 5
        let ins_ops = buf.local_insert_str(5, " Skulls", "peer-alice");
        assert_eq!(ins_ops.len(), 7);
        assert_eq!(buf.to_string(), "Hello Skulls");
    }

    #[test]
    fn test_crdt_concurrent_convergence() {
        // Alice and Bob start with the same document
        let initial_text = "fn compute() {\n}\n";
        let initial_buf = CrdtBuffer::from_str(initial_text, "genesis");
        let mut alice_buf = initial_buf.clone();
        let mut bob_buf = initial_buf.clone();

        // Alice inserts a header comment at index 0
        let alice_ops = alice_buf.local_insert_str(0, "// Module: Math\n", "alice");

        // Bob simultaneously inserts code inside function at index 14
        let bob_ops = bob_buf.local_insert_str(14, "    let result = 42;\n", "bob");

        // Exchange operations across P2P swarm
        alice_buf.apply_remote_ops(&bob_ops);
        bob_buf.apply_remote_ops(&alice_ops);

        // Both buffers MUST converge to the exact same string
        let alice_res = alice_buf.to_string();
        let bob_res = bob_buf.to_string();
        assert_eq!(alice_res, bob_res, "CRDT buffers did not converge!");
        assert!(alice_res.starts_with("// Module: Math\n"));
        assert!(alice_res.contains("let result = 42;"));
    }

    #[test]
    fn test_crdt_session_manager_and_cursor_registry() {
        let mgr = CrdtSessionManager::new();
        let path = "src/main.rs";

        let content = mgr.get_or_init_buffer(path, "println!(\"hi\");", "peer-me");
        assert_eq!(content, "println!(\"hi\");");

        // Update cursor
        mgr.update_cursor("alice", path, 10, 4);
        let cursors = mgr.get_active_cursors(path);
        assert_eq!(cursors.len(), 1);
        assert_eq!(cursors[0].peer, "alice");
        assert_eq!(cursors[0].line, 10);
        assert_eq!(cursors[0].col, 4);

        // Local change
        let ops = mgr
            .apply_local_change(path, 0, 0, "// header\n", "peer-me")
            .unwrap();
        assert_eq!(ops.len(), 10);
        assert_eq!(
            mgr.get_content(path).unwrap(),
            "// header\nprintln!(\"hi\");"
        );
    }
}
