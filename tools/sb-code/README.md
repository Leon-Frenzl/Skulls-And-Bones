# S&B Code (`sb-code`)
**Sovereign Unified Code Engine: AST Scopes, Live Swarm & BLAKE3 Merkle VCS**

Part of the [Skulls & Bones](https://skulls-and-bones.org) developer suite.

## The Core Innovation
1. **AST-Scoped Isolation**: Methods, functions, and structs are isolated scopes. Two developers never overwrite the same function concurrently, but can freely work on different functions in the same file without conflict.
2. **Stable Shadow Baseline (Dual-View Compilation)**: Colleagues always compile and test against the last known stable version of your method while you are actively editing, preventing broken syntax from poisoning team builds.
3. **BLAKE3 Merkle-DAG VCS**: Fast, sovereign version control without a hosted code-provider dependency. Commit and tree IDs are content-derived; commits are currently unsigned.
4. **Multi-Target Execution Runner**: Switch seamlessly between `LOCAL`, `NODE: sb-node`, and `HOST` execution targets.
5. **Universal LSP Proxy**: Compatible with any code editor (Neovim, VS Code, JetBrains, Helix) via standard Language Server Protocol.

## Mesh repository sync

`sb-code syncd` serves one initialized workspace on loopback port `58832`, or on the workspace-assigned code-sync port for a managed workspace. It is intended to be reached only through the `sb-node` Cross-Mesh Bridge. On the node, start the service with:

```powershell
sb-code syncd --workspace C:\work\project
```

Add an explicit Cross-Mesh route to `dev-mesh:58832` and grant authorized members both `stream:transfer` and `code:sync`; neither the port nor the capability is granted by default. A route that requires a Cross-Mesh capability token can be supplied on the client as a JSON file:

```powershell
sb-code push --source-mesh app-mesh --target-mesh dev-mesh --anchor 203.0.113.10:58888 --branch main --workspace C:\work\project
sb-code pull --source-mesh app-mesh --target-mesh dev-mesh --anchor 203.0.113.10:58888 --branch main --workspace C:\work\project
```

Append `--capability-token C:\path\to\token.json` when the configured route requires a token. A managed workspace's assigned port is printed by `sb-code workspace add` / `sb-code workspace list`; pass it as `--service-port <port>` to `push`, `pull`, or `divergence` when targeting that workspace. Configure the corresponding Cross-Mesh route to the same port. Push and pull transfer validated BLAKE3 bundles and reject malformed objects, dirty checked-out workspaces, and non-fast-forward updates. Commit signatures are not yet implemented; mesh authorization controls who may sync, but does not cryptographically authenticate the `author_callsign` field.

External clients and developer frontends (such as the satellite `sb-studio`) use this same `sb-code` mesh-sync API for Version History push/pull. The sync API takes the source mesh, target mesh, anchor socket address, and an optional capability-token file path, reflecting the actual connection and authorization result after a stream operation.

## Repository web viewer

On the machine that stores the repository, start the viewer. Its Mesh-facing
service stays read-only, binds to loopback only, and serves branch history,
commit metadata, changed-file lists, diffs, trees, and UTF-8 blobs up to 512 KiB:

```powershell
sb-code web --workspace C:\work\project
```

On the `sb-node` anchor, permit a source mesh to reach the viewer in
`dev-mesh`; the route is limited to port `58835`:

```powershell
sb-node route add-code-web --source-mesh app-mesh --target-mesh dev-mesh
```

Restart the `sb-node` daemon after changing routes so it reloads the policy.
Grant intended viewers both `stream:transfer` and the separate `code:view`
membership capability. `code:sync` does not imply read access and `code:view`
does not grant push or pull access. On a member workstation, start the local
loopback tunnel and open its URL in a browser:

```powershell
sb-code web-proxy --source-mesh app-mesh --target-mesh dev-mesh --anchor 203.0.113.10:58888 --workspace C:\work\project
```

Grant viewer access in the requesting mesh, for example:

```powershell
sb-node member add --mesh app-mesh --name reviewer --pubkey <member-public-key> --role Auditor --caps stream:transfer,code:view
```

Open `http://127.0.0.1:58836`. The browser talks only to the local proxy; each
connection is forwarded through an authenticated Mesh stream to the viewer.
The web UI can inspect commit and working-tree diffs and create local commits.
Push and pull run from the local proxy through the existing Mesh sync service;
they do not add write access to the viewer. The proxy workspace must be the
same local repository, and the requesting member must also have the existing
`code:sync` permission on the sync route. If that route requires a capability
token, pass `--capability-token C:\path\to\token.json`; use `--service-port`
when the sync service is configured on a non-default port. Both the viewer and
proxy refuse non-loopback bind addresses. Remove viewer access with
`sb-node route remove-code-web --source-mesh app-mesh --target-mesh dev-mesh`.

## Deferred AST conflicts

When a plan has scopes requiring a manual decision, persist a three-way record without changing the working tree, resolve each scope, then finalize only while both branch heads still match the recorded heads:

```powershell
sb-code conflicts begin feature-x
sb-code conflicts list
sb-code conflicts resolve <scope-id> --use current
sb-code conflicts resolve <scope-id> --use other
sb-code conflicts finalize
sb-code conflicts discard
```

The conflict record is atomically written to `.sb/conflicts.json`. A decision is limited to choosing the complete current or other scope; it does not synthesize code. Finalization revalidates the branch heads and requires every decision.

## Managed workspaces

Create a separate checkout that shares the content-addressed `.sb/vcs` object store while keeping its working files, `HEAD`, baseline, and assigned service ports isolated:

```powershell
sb-code workspace add feature-x C:\work\feature-x
sb-code workspace list
sb-code checkout feature-x --workspace C:\work\feature-x
sb-code workspace remove C:\work\feature-x
sb-code workspace prune
```

Branch refs are shared by workspaces. If another workspace advances the checked-out branch, the older checkout can still be reviewed against its saved baseline but cannot commit or integrate until refreshed with `checkout <branch>`. Concurrent ref updates are serialized and stale writes fail instead of overwriting the newer head. Assigned port ranges reserve slots for code sync, drive sync, AST locks, and a dev server; currently `syncd` automatically binds the assigned code-sync slot, while the other slots are reservations for their respective service launchers.

`workspace remove` unregisters and removes only a verified managed workspace. It refuses dirty or behind workspaces unless `--force` is supplied. `workspace prune` only removes registry entries whose working directory is already missing; it does not delete files. Registry and branch-ref synchronization uses OS-backed advisory file locks, which are released when a process exits unexpectedly.

## Mesh branch divergence radar

`sb-code divergence` asks a remote `syncd` to advertise branch heads and changed AST-scope IDs since each known local head:

```powershell
sb-code divergence --source-mesh app-mesh --target-mesh dev-mesh --anchor 203.0.113.10:58888 --service-port 59000
```

The control protocol has a bounded 4 MiB frame limit and includes up to 16,384 known ancestor IDs so peers can find a common commit without transferring commit objects first. Studio distinguishes an empty remote repository, synchronized branch heads, divergence without a known common base, and connection/protocol errors. Older `syncd` versions continue to support push/pull; the radar reports explicitly when the remote does not implement branch listing. Scope overlaps are structural signals only; they do not prove a semantic conflict.

## End-to-end smoke test

Exercise separate TCP-connected repositories through initial push and pull, concurrent edits to the same AST scope, branch-radar overlap reporting, and persisted conflict resolution:

```powershell
cargo test -p sb-code --test mesh_sync_smoke_test
```

## Mesh AST scope-lock smoke test

The live stream test routes two simulated Mesh peers through port `58834`. It verifies owner-bound claims, heartbeat renewal, same-scope collision rejection, and rejection of another peer's release attempt:

```powershell
cargo test -p sb-code stream_lock_authority_rejects_conflicts_and_unowned_mutations
```

## AST Ghost Image and safe integration

New commits include content-addressed snapshots of recognized syntax scopes and
non-whitespace opaque regions that the parser cannot classify. Snapshot version 3
uses Tree-sitter adapters for Rust, TypeScript, TSX, and Java. Each scope records
its parser and adapter version. Additional languages can implement
`LanguageAdapter` and register it with `register_language_adapter`; unsupported
extensions and files with syntax errors remain opaque rather than being guessed;
their parser diagnostic is stored with the scope snapshot.
Version 1 and 2 snapshots are validated using their original parser and
deterministically re-projected from the content-addressed tree at comparison
time; old commits are not rewritten. Compare
the checked-out branch with another branch and inspect a scope's base/current/ghost
versions with:

```powershell
sb-code ghost feature-x
sb-code ghost feature-x --scope calculate_total
```

Integrate independent changes to uniquely identified AST scopes:

```powershell
sb-code plan feature-x
sb-code plan feature-x --json
sb-code integrate feature-x
```

CLI locks, Studio scopes, local IPC claims, and live AST-diff routing all use the
same registered language adapter and scope IDs as VCS snapshots. Opaque regions
cannot be exclusively locked or applied through live AST streaming; patches are
parsed and checked against the same scope ID before any file is written.

The plan reports proposed actions, manual decisions, blocked reasons, candidate
test scopes, and the exact branch heads it describes. Studio displays this plan
before applying it and refuses to apply it if either head changed in the
meantime. Integration requires a clean workspace. Merge decisions are made per
recognized AST scope rather than per file. Independent scope additions, edits,
deletions, and AST-only file creation/removal can be integrated when their
identities and placement are unambiguous. Opaque regions can be replaced
automatically only when a stable region exists unchanged on the current side;
structural Opaque changes and conflicts require manual review. Changes not
covered by AST or opaque snapshots, ambiguous identities, or unsafe insertion
points are rejected rather than guessed. Test-scope candidates are heuristic,
not a complete dependency analysis. Successful integration creates an
append-only commit with both branch heads as parents. AST snapshots are
versioned and included in commit IDs and mesh bundles. The current deterministic
parser recognizes only supported syntactic patterns; the ghost view and patch
safety checks do not prove semantic or behavioral compatibility.

## History analysis and outline

`sb-code heatmap` and `sb-code coupling` read analysis exclusions from the
workspace-root `.sbignore`. The same gitignore-style rules also exclude matching
files from versioning and sync. Secret files also have unconditional kernel
exclusions. Pass `--all` to bypass the filter for one analysis run; it does not
change tracking or sync behavior.
`sb-code outline <file>` shows Rust `impl` blocks and inline `mod` blocks as
containers, with their contained scopes indented beneath them.

Read commands that accept `--json` use the envelope
`{ "schema_version": 1, "command": "...", "data": ... }`. For agent review
context use `sb-code context --repo --json --max-chars 20000`; the Markdown form
is the default. History inspection includes `show <commit>`, `why <file> <scope>`,
and `log --graph`. `diff --scopes [file]` summarizes AST additions, removals,
and modifications.

Commits can be previewed without writing objects using
`sb-code commit -m "..." --dry-run`. Select whole files/directories with
`--only <path>` or recognized existing AST scopes with
`--scope <file>=<scope-name-or-id>`; independent unselected edits remain in
the working tree. The preview validates these selectors just like a commit;
JSON output includes the validated `selected_paths` and
`selection_valid` fields. New scopes must currently be committed with `--only`.
`sb-code checkpoint <name>` creates a normal commit plus a named local
checkpoint reference, which can be restored with `sb-code checkout <name>`.
`Cargo.lock` is intentionally not ignored so Rust dependency resolution remains
reproducible.

FastCDC chunks and manifests are derived cache data, not canonical VCS objects.
Commits store verified raw blobs only; chunk manifests are derived from those
blobs when requested, and individual chunks can be resolved on demand. The
chunk lookup index is built once per engine instance and invalidated when blobs
are added, avoiding repeated full-blob scans without persisting another cache.
Older repositories with persisted FastCDC caches remain readable.

New commit objects are compact-JSON serialized and gzip-compressed as
`<commit-id>.json.gz`; commit IDs still cover the canonical commit fields, not
the storage encoding. Existing uncompressed `<commit-id>.json` objects remain
readable and mesh bundles continue to carry uncompressed JSON inside their
outer compressed archive. AST snapshots benefit from the repeated-field
compression without changing their versioned schema. `sb-code stats` reports
no deduplication ratio when no chunk cache is present.
