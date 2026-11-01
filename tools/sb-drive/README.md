# `sb-drive` Mesh Stream

The peer-file stream exposes read-only access to a configured directory over the
authenticated Mesh stream transport. The service itself binds to loopback only;
`sb-node` is responsible for relaying the stream between meshes.

Start the service on the peer that hosts the files:

```text
sb drive serve --root <directory> --mesh <host-mesh> [--catalog <object-catalog.json>]
```

Add an explicit, capability-token-protected route on the anchor:

```text
sb-node route add-drive --source-mesh <requesting-mesh> --target-mesh <host-mesh>
```

The service reads the host mesh's RBAC store and object catalog for every
download. The requester must have active membership in that mesh and `Read`
permission on the unique current object version whose `sb-drive` payload
locator exactly matches the requested relative path. Missing or ambiguous
catalog entries, stale versions, unavailable policy files, and denied ACLs fail
closed. The service must bind to loopback and be registered by `sb-node` on
port `58833`.

Download a file through the authenticated source mesh identity and the
authorized route:

```text
sb-drive open @<peer>:/<catalog-locator> --mesh <source-mesh> --target-mesh <host-mesh> --anchor <anchor-ip>:58888 [--token <capability.json>]
```

`open` requires an already registered source-mesh identity. It verifies the
downloaded SHA-256 against the current catalog version before opening the local
cache copy. A token file, when supplied, must be a regular non-symlink file no
larger than 16 KiB.

The stream v2 protocol uses `sb-app-protocol` transfer offers and bounded
binary chunks, limits each file to 256 MiB, rejects absolute paths, traversal,
symbolic links, Windows alternate-data-stream syntax, and reserved Windows
path components, and verifies chunk and whole-transfer SHA-256 digests before
publishing the downloaded cache file. Its request still uses the legacy
relative locator; operation-grant and broker integration remain in progress.
Consumers can use
`sb_drive::stream::download_from_mesh` with a `MeshClient` and an authorized
capability token. `sb drive get` remains the existing SSH-based command.

The in-process live mesh transfer smoke test verifies streamed cache contents and rejects a traversal path at the remote service:

```text
cargo test -p sb-drive live_mesh_stream_downloads_peer_file_into_verified_cache
```
