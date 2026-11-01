# S&B Code (`sb-code`) — Roadmap & TODOs
> **Sovereign Unified Code Engine: AST Scopes, Merkle VCS, CRDT & P2P Swarm**  
> Autarke Single-Binary & Core Library (100% Rust / Tokio / Ratatui)  
> *Sicherheitsmarke: Skulls & Bones ([skulls-and-bones.org](https://www.skulls-and-bones.org))*

---

## 🎯 Produkt-Vision
`sb-code` vermeidet die Abhängigkeit von zentralen Code-Providern und proprietären Kollaborations-Diensten. Es kombiniert:
1. **BLAKE3 Merkle-DAG Versionskontrolle**: Lokales, dezentrales VCS ohne Cloud-Host.
2. **"Figma für Code" AST Scope Locking**: Granulare Funktions-/Methoden-Sperren statt sperriger Dateisperren.
3. **Dual-View Stable Shadow Baseline**: Peers kompilieren stets gegen die fehlerfreie Baseline, während du schreibst.
4. **LSeq Sequence CRDT**: Konfliktfreie kollaborative Multi-Cursor Puffer für ungesperrte Code-Zonen.
5. **P2P Swarm Commit Sync**: Direkter Commit-Austausch über dezentrale Mesh Anchors.

---

## 📋 Entwicklungs-Phasen

### Phase 1: BLAKE3 Merkle-DAG Version Control (Status: 🟢 Erledigt & Verifiziert)
- [x] **Content-Addressed Storage (CAS):**
  - [x] BLAKE3 Hash-Identifikation für Blobs (`.sb/vcs/objects/blobs/`).
  - [x] Merkle-Bäume (`.sb/vcs/objects/trees/`) und signierte Commits (`.sb/vcs/objects/commits/`).
- [x] **Branching & HEAD Pointer:**
  - [x] Branch-Referenzen (`.sb/vcs/refs/heads/<branch>`) und atomarer HEAD-Pointer (`.sb/vcs/HEAD`).
- [x] **LCS Unified Line Diff & Status Engine:**
  - [x] Zeilengenauer Diff-Berechner (`+`, `-`, ` `) und Erkennung von `modified`, `added`, `deleted`.
  - [x] Strikte Kernel-Ausschlussregeln (`.sbkey`, `.env`, Legacy-`.git`-Metadaten, `target`) sowie `.sbignore`.
- [x] **Atomarer Checkout & Rollback:**
  - [x] `VcsEngine::checkout` stellt beliebige historische Commits oder Branches aus CAS-Blobs wieder her.
- [x] **CLI Subcommands:** `sb code init`, `sb code status`, `sb code commit`, `sb code log`, `sb code diff`, `sb code branch`, `sb code checkout`.

---

### Phase 2: AST Scope Locking & Dual-View Baseline (Status: 🟢 Erledigt & Verifiziert)
- [x] **AST Parser & Scope Extraction:**
  - [x] Automatische Erkennung von Funktionen, Methoden, Klassen, Structs und Enums.
- [x] **Exklusive AST-Sperren (`AstLockTable`):**
  - [x] Granulare Methoden-Locks mit flüchtiger 180s Lease-TTL und Heartbeat-Verlängerung.
  - [x] Zombie-Lock-Prävention: Automatisches Bereinigen abgelaufener Peer-Locks.
- [x] **Dual-View Compiling Baseline (`BaselineCache`):**
  - [x] Speichern stabiler Funktionsstände (`save_stable_scope`).
  - [x] `render_dual_view_content`: Ersetzt in Bearbeitung befindliche WIP-Funktionen durch die letzte fehlerfreie Version für andere Peers.

---

### Phase 3: LSeq CRDT Multi-Cursor Buffer (Status: 🟢 Erledigt & Verifiziert)
- [x] **LSeq / Fractional Indexing Sequence CRDT (`CrdtBuffer`):**
  - [x] Globale Position-IDs (`pos: Vec<u32>`, `peer: String`, `clock: u64`) für mathematisch beweisbare Konvergenz.
  - [x] Batch-Operationen (`local_insert_str`, `local_delete_range`).
- [x] **Multi-Cursor Presence Registry:**
  - [x] Übertragung von Peer-Cursorpositionen (`broadcast_peer_cursor`) und Caret-Rendering mit Nametags.

---

### Phase 4: P2P Swarm Commit Sync (`sb code push/pull`) (Status: 🟢 Erledigt & Verifiziert)
- [x] **Deduplizierte Merkle-Bundles (`tar.gz`):**
  - [x] Berechnung der Commit-Differenz gegen den Ziel-Anchor (`since_commit`).
  - [x] Verpackung neuer CAS-Blobs und atomarer Transfer in den Anchor Store (`~/.sb/vcs-store/<anchor>/<project>/`).
- [x] **Fast-Forward Swarm Pull:**
  - [x] Automatische Übernahme von Manifesten und CAS-Blobs sowie Aktualisierung des lokalen Arbeitsverzeichnisses.
- [x] **Divergenz-Prüfung (`remote-status`):**
  - [x] Ermittlung des Synchronisationszustands (`in_sync`, `ahead`, `behind`).

---

### Phase 5: Sovereign Merge Requests (SMR) & P2P Code Review (Status: 🟡 In Planung)
- [ ] **SMR Merkle-Objekt (`MergeProposal`):**
  - [ ] Neues signiertes Merkle-Objekt mit Quell-/Ziel-Branch, Commit-Range, Titel und Ed25519-Signatur.
- [ ] **AST-Scoped Inline Review Comments:**
  - [ ] Kommentare werden an die unveränderliche AST-Scope-ID (`file::fn:name`) geheftet.
  - [ ] Kommentare bleiben bei Zeilenverschiebungen und Refactorings stabil an der Funktion verankert.
- [ ] **Kryptographische Approval Gates (4-Augen Quorum):**
  - [ ] Konfigurierbare Branch-Policies (z. B. `main` erfordert mindestens 2 signierte Approvals berechtigter Swarm-Peers vor Merge).
- [ ] **CLI Subcommands:**
  - [ ] `sb code review create <target-branch>`
  - [ ] `sb code review list`
  - [ ] `sb code review approve <mr_id>`
  - [ ] `sb code review merge <mr_id>`
