# S&B Mesh DNS and Directory Contract

> **Status:** Architecture contract for implementation; not a claim that the
> described behavior is already implemented.
> **Contract version:** `sbm-directory/v1`
> **Scope:** Mesh-scoped naming, service discovery, and client-side split DNS.

## 1. Goals and non-goals

`sb-dns` provides the Magic-DNS experience for S&B meshes: enrolled nodes and
approved services receive stable, human-readable names that resolve on every
authorized mesh client without manual host-file edits.

The directory is authoritative per mesh, not per anchor. A mesh may have
multiple redundant authority replicas, but only a currently fenced leader may
commit directory changes or issue authority-signed updates. Anchors provide
mesh reachability and may host authority replicas; being an anchor alone does
not grant authority.

DNS is discovery, not authorization. A DNS answer never grants permission to
connect, proves a peer's identity, or replaces an `sb-mesh` ticket or
capability check. Mesh identity, service authorization, transport encryption,
and routing policy remain separate checks.

`sb-dns` does not replace public DNS hosting or become a public recursive
resolver. Public names continue through explicitly configured upstream
resolvers; private mesh names must never be forwarded outside the mesh.

## 2. Names and resolution model

The canonical name is scoped by the mesh:

```text
<node-or-service>.<mesh>.sbm
```

Examples:

```text
api.dev.sbm
api.prod.sbm
anchor-01.dev.sbm
```

The same label may exist in different meshes. The fully qualified name is
unambiguous and does not depend on a client's active mesh. Mesh names and
labels are lowercase ASCII DNS labels, validated and normalized at enrollment;
each label is 1-63 octets and the full name obeys DNS name length limits.

For a service record named `api.dev.sbm`, the SRV owner is
`_api._tcp.dev.sbm` or `_api._udp.dev.sbm`, according to the registered
protocol. The SRV target remains the enrolled node's canonical FQDN.

Short petnames such as `nas` are client-local aliases only. They may point to a
canonical mesh FQDN but cannot claim or shadow a canonical name. If the client
has ambiguous local aliases, resolution must report ambiguity rather than
selecting an arbitrary mesh.

Mesh records are private data. A client resolves them through its local
`sb-dns` resolver or another explicitly configured mesh-aware resolver. OS
split-DNS sends only the `.sbm` namespace to that resolver. If the mesh resolver
is unavailable, `.sbm` queries fail locally; they are never sent to public
upstreams.

## 3. Authority and replication

Each mesh has one logical authority identified by a pinned authority public-key
set and a stable mesh ID. Authority replicas share an ordered directory log
and signed snapshots. Replicas are read-only unless elected and fenced as the
current writer.

The writer lease and fencing term must be backed by a quorum of configured
authority replicas. Every committed mutation and signed snapshot is bound to a
monotonically increasing term and revision. A replica or former leader with an
older term cannot publish accepted updates after a newer term is committed.
This contract does not permit an uncoordinated standby to promote itself:
without a quorum it cannot safely establish that the previous writer is
fenced.

When quorum is lost:

- New names, service registrations, membership changes, revocations, and
  ticket issuance stop.
- Clients and anchors may use a previously verified snapshot only until its
  signed validity deadline.
- Leases may not be extended from a stale replica or by changing local clocks.
- Expired or revoked records are not returned as live answers.
- Restoring quorum resumes writes only after term and revision reconciliation.

This deliberately prefers consistency and authorization safety over write
availability during a partition. DNS read availability is bounded by the
validity of the last trusted snapshot and its individual leases.

## 4. Enrollment, leases, and record ownership

Enrollment is an authenticated control-plane operation, not a DNS update.

1. An administrator creates a one-time, mesh-scoped enrollment grant with a
   short expiry and explicit node role/policy.
2. The server generates and persists its own node identity locally, presents
   proof of possession, and redeems the grant through an authenticated
   `sb-mesh` channel.
3. The authority approves the node ID, mesh membership, assigned canonical
   name, overlay address, and permitted service-registration policy.
4. The node receives a signed membership credential and a lease. Secrets and
   private identity keys are never sent in DNS records or ordinary logs.

Names are assigned by policy and protected by a uniqueness constraint within a
mesh. A node cannot overwrite another node's name by merely asserting it.
Renames, transfers, and service ownership changes are explicit audited
mutations; old names receive tombstones so stale replicas cannot resurrect
them.

An online node renews its lease with an authenticated heartbeat. The authority
records `lease_expires_at`, monotonically increasing `revision`, and the
membership state. A missed heartbeat does not immediately prove compromise:
the name becomes unavailable after its lease expires. A revoked node is
removed from active answers immediately after the revocation reaches a trusted
snapshot; disconnected clients may retain old data only until that snapshot's
bounded expiry.

## 5. Version 1 directory objects

The versioned control-plane envelope uses an explicit `schema` field and
rejects unknown major versions. It is transported over authenticated,
encrypted `sb-mesh` control traffic, not exposed as a new unauthenticated
Internet protocol.

An authoritative node entry contains at least:

```text
schema                 "sbm-directory/v1"
mesh_id                stable cryptographic mesh identifier
mesh_name              canonical DNS label used in mesh FQDNs
fqdn                   canonical <node>.<mesh>.sbm name
node_id                cryptographic sb-mesh node identity
identity_key_id        fingerprint of the enrolled public identity
overlay_addresses      zero or more assigned mesh IPv4/IPv6 addresses
owner_id               authenticated principal responsible for the entry
state                  active | revoked | tombstone
revision               monotonic per-mesh committed revision
lease_expires_at       absolute UTC expiry, signed by authority
authority_term         fencing term of the writer
authority_key_id       key identifier selected from the pinned mesh set
signature              authority signature over canonical serialized fields
```

An approved service entry contains at least:

```text
schema                 "sbm-directory/v1"
mesh_id                stable cryptographic mesh identifier
mesh_name              canonical DNS label used in mesh FQDNs
service_fqdn           canonical service name, e.g. api.dev.sbm
target_node_id         enrolled node identity hosting the service
service_protocol       registered protocol (for example tcp)
service_port           authorized service port
owner_id               authenticated service owner
state                  active | revoked | tombstone
revision               monotonic per-mesh committed revision
lease_expires_at       no later than the hosting node's lease
authority_term         fencing term of the writer
authority_key_id       key identifier selected from the pinned mesh set
signature              authority signature over canonical serialized fields
```

Signatures cover a deterministic, versioned encoding and all fields that affect
identity, routing, ownership, or validity. The verifier obtains trusted
authority keys from the locally enrolled mesh configuration; it must not trust
a public key merely because that key is carried by the object being verified.
Unsupported algorithms, malformed canonical encodings, invalid signatures,
unknown authority keys, stale terms, and expired leases fail closed.

Service registrations require both node proof of possession and an authority
policy decision. The DNS directory may advertise an approved service and its
target, but the client still obtains the appropriate mesh ticket/capability
before connecting. DNS responses do not carry bearer authorization.

### Local authority trust configuration

The resolver pins authority public keys locally in
`~/.sb/dns/config.json`; the configuration field is an array of mesh entries.
Each mesh entry has a stable `mesh_id` and a `pinned_keys` map from
`authority_key_id` to a 32-byte Ed25519 public key encoded as 64 hexadecimal
characters:

```json
{
  "authority_trust": [
    {
      "mesh_id": "mesh-dev-01",
      "pinned_keys": {
        "auth-1": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
      }
    }
  ]
}
```

The sample key is illustrative only; replace it with the authority public key
verified during authenticated mesh enrollment. Private signing keys must never
be stored in this client configuration. `sb-dns serve` rejects malformed keys,
invalid mesh trust entries, and duplicate mesh IDs rather than silently
starting without the requested pins. Older configurations without
`authority_trust` remain valid and pin no authorities.

### Signed directory snapshot file

`sb-dns serve` loads `~/.sb/dns/directory-snapshots.json` as a JSON array of
`sbm-directory-snapshot/v1` envelopes. Each envelope binds one mesh, authority
term, committed revision, validity deadline, signing key ID, mesh name, node
records, service records, and an Ed25519 signature. The envelope mesh name
must match every enclosed record. The signature covers a
domain-separated deterministic encoding of all envelope metadata and the
canonicalized serialized record arrays; every record's own authority
signature is independently checked against the locally pinned key set.

The complete file is size-bounded (16 MiB), each snapshot is bounded to 50,000
records, and duplicate snapshots for a mesh are rejected. A snapshot must be
current, match a locally pinned mesh authority, contain only valid signed
records within its term/revision, avoid duplicate names and node identities,
and reference valid active targets for active services. Any invalid snapshot
prevents startup; no partial snapshot is published. A valid snapshot replaces
that mesh's previous in-memory directory atomically, and answers expire no
later than either their record lease or the snapshot validity deadline.

The top-level JSON value is an array. Each snapshot object uses the struct
field names from `DirectorySnapshot` (`schema`, `mesh_id`, `mesh_name`,
`authority_term`, `revision`, `valid_until`, `authority_key_id`, `nodes`,
`services`, and `signature`). Signatures are JSON byte arrays as emitted by
Serde for `Vec<u8>`; individual node/service objects use the fields documented
above, including their own byte-array signatures.

An absent snapshot file is allowed, but `serve` warns that private names will
not resolve. Install the JSON array using the enrolled authority's snapshot
signing key and keep private signing keys out of this client directory. This
file is currently provisioned out-of-band; snapshot production, authenticated
transport, refresh, and durable anti-rollback state across restarts remain
future work. Because local anti-rollback cursors are currently in-memory,
operators must protect the snapshot file from rollback until persistent cursor
state is implemented.

## 6. DNS behavior

`sb-dns` serves standards-compliant DNS over UDP and TCP to configured local or
mesh interfaces. Production packet parsing, serialization, truncation, and
transport behavior use Hickory Protocol rather than the legacy partial
hand-written codec.

Version 1 answers:

- `A` and `AAAA`: assigned overlay addresses for an active node or service
  target, with TTL no longer than the remaining signed lease.
- `CNAME`: only explicitly approved aliases within the same mesh namespace;
  loops and cross-mesh implicit aliases are rejected.
- `SRV`: approved service protocol/port and canonical target, where the
  requesting policy permits service discovery.
- `TXT`: reserved for bounded, non-secret metadata and versioned diagnostics;
  never for credentials, tickets, or private keys.
- `PTR`: reverse lookup only for address ranges explicitly assigned to that
  mesh, with responses derived from the same verified directory snapshot.

Unknown names inside a configured private mesh zone return authoritative
`NXDOMAIN`. Unsupported record types return the appropriate DNS response and
are not silently treated as `ANY`. Queries for public names may be forwarded
only when upstream forwarding is enabled. The resolver must validate the
upstream response ID, source, response bit, and question before accepting it;
cache entries are keyed by canonical name, type, class, and relevant policy
scope, and expire no later than the minimum answer TTL.

The resolver must bound packet size, compression-pointer traversal, label and
record counts, outstanding upstream queries, cache memory, and concurrent
client work. Malformed packets receive a DNS format error or are dropped
according to the DNS library's safe behavior; they must not panic the service.

## 7. Client discovery and cache rules

An enrolled client receives mesh ID, pinned authority keys, resolver/anchor
endpoints, and the last verified directory snapshot through its authenticated
mesh configuration. Snapshot and incremental update application is atomic:
verify the complete update, term, revision, signature, and expiry before
publishing any part of it to DNS answers.

Clients reject rollback to a lower committed term or revision. Cache lifetime
is bounded by both DNS TTL and signed record expiry. A local stale answer must
not outlive its authority lease. Revocation updates invalidate matching cache
entries and active service-discovery state; service connections still enforce
authorization independently.

Authority and resolver discovery is separate from trust. A discovered endpoint
is accepted only after its node identity and authority proof match the enrolled
mesh configuration.

## 8. Availability and operations

`sb-node` owns anchor lifecycle, mesh transport, peer reachability, and optional
hosting of a `sb-dns` authority replica. `sb-dns` owns directory state,
authority replication/election integration, DNS serving, and client split-DNS
configuration. `sb-proxy` is an optional registered service; it does not own
mesh names or authority keys. Local socket/port auditing diagnostics may report
local TCP/UDP bindings and exposure but cannot mutate directory membership or
terminate production services automatically.

An anchor health report distinguishes at least:

- local process/listener health;
- mesh transport and peer reachability;
- authority replica freshness, current term, and quorum/write readiness;
- DNS listener and snapshot freshness;
- optional registered-service health.

“Anchor online” must not imply “authority writable” or “all services healthy.”
Use supervised systemd/Windows-service operation, orderly shutdown,
structured logs, startup validation, and bounded retry with backoff.
High availability requires multiple anchors/replicas in independent failure
domains and client support for trying alternate enrolled anchors.

Split-DNS setup must be reversible and scoped to `.sbm`; it must preserve
pre-existing OS resolver policy. Setup, teardown, and status operations report
unsupported platforms and permission failures rather than claiming success
after printing manual instructions.

## 9. Implementation boundaries and migration

The current `sb-dns` static records and partial DNS codec are prototypes, not
the directory authority described here. `sb-mesh` already has experimental
signed zone records, canonical node lookup, and local petnames. Those concepts
may be reused, but must be reconciled with this contract:

- Authority keys must be pinned by enrolled mesh configuration.
- Names, records, and pets must use the canonical mesh-scoped form.
- Signed records must bind mesh ID, owner, revision, term, and expiry.
- The in-memory zone store must become verified, persistent, replicated
  directory state.
- Peer-file lookup must not act as an authority or bypass lease/revocation
  checks.
- Existing static configuration must not be silently promoted into trusted
  mesh records.

Implement in independently verifiable phases:

1. **Contract and validation:** canonical names, mesh scoping, versioned
   directory types, pinned-authority verification, lease/revision validation,
   and adversarial unit tests.
2. **Local resolver foundation:** standards-compliant DNS UDP/TCP serving,
   private-zone fail-closed behavior, safe upstream forwarding, bounded cache,
   and parser/fuzz tests.
3. **Mesh client integration:** signed snapshots and incremental updates over
   authenticated `sb-mesh` control traffic; atomic application and
   multi-anchor discovery.
4. **Authority service:** enrollment, name allocation, service approval,
   leases, revocation, audit log, durable snapshots, and quorum-backed leader
   fencing/standby replication.
5. **OS integration and operations:** reversible Windows NRPT, Linux
   systemd-resolved, macOS support, service units, health reporting, and
   failure/restart tests.
6. **Service consumers:** register `sb-proxy` services with explicit policy;
   expose non-destructive socket health/exposure observations.

Each phase must preserve fail-closed behavior for private names and must not
describe an unimplemented phase as production-ready.

## 10. Acceptance criteria

- Two meshes can contain the same short hostname and resolve different,
  stable mesh-scoped FQDNs on one client.
- A forged self-signed record, an unpinned authority key, a stale-term update,
  a lower revision, and an expired lease are all rejected.
- A non-authority node cannot claim, overwrite, or renew another node's name.
- Concurrent duplicate enrollment/name claims produce one authoritative
  result and an auditable conflict.
- A revoked or expired node/service is not returned from a fresh snapshot;
  cached answers never exceed their signed expiry.
- Loss of authority quorum stops writes and ticket issuance while valid
  snapshots remain usable only within their bounded validity.
- Failure to resolve `.sbm` never leaks the query to a public DNS upstream.
- Public DNS forwarding remains optional and validates the matching response.
- Malformed and oversized DNS packets cannot crash the resolver or allocate
  unbounded memory.
- Split-DNS setup and teardown preserve unrelated system resolver settings.
- Anchor health differentiates transport, authority, DNS, and optional
  service state; tests exercise restart, partition, stale replica, and
  failover behavior.