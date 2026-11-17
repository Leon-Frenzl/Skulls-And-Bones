# Skulls & Bones Mesh Application Profile (SB-MAP)

**Version:** Draft 0.1
**Status:** Proposal for maintainer review; Rust contract and bounded wire-transfer primitives exist, but this is not an adopted or end-to-end integrated protocol
**Language:** English for normative protocol terms; project notes in German
**Scope:** Application packages, service APIs, identity, authorization, distribution, and execution in the Skulls & Bones Mesh

> **Architektur- und Konsolidierungshinweis (Milestone M3):**
> Die in dieser Spezifikation referenzierten grafischen Desktop-Clients (`sb-desktop`, `sb-studio`, `sb-workbench`) sowie `netgrid` wurden im Rahmen der 14-Core-Konsolidierung aus dem Kern-Repository als eigenständige externe Satelliten-Applikationen ausgelagert. SB-MAP verbleibt als architektonische Spezifikation für Client-Service-Verträge, Anwendungs-Manifeste und isolierte Mesh-Dienste über `sb-app-contract`, `sb-app-protocol` und `sb-mesh`.

## 1. Purpose and design decision

SB-MAP defines how a developer builds an application whose user interface is a native Rust program and whose protected business logic or data is provided by an authorized Mesh service. It aims to let developers build against a stable library instead of implementing discovery, transport, authorization, packaging, and sandbox policy independently.

The Mesh is a service and artifact network, not a remote desktop or a trusted code-execution channel. A native UI runs locally in the desktop's operating-system sandbox. A remote service runs on a Mesh node under that node's execution policy. The Mesh may distribute signed artifacts, but it MUST NOT cause the desktop to execute a remote UI, script, or binary merely because the artifact is discoverable or signed.

This is an S&B profile proposal, not a claim of IEEE, IETF, or other standards-body approval. Its requirement words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html).

## 2. Standards review and what is reused

No reviewed standard provides the whole application model in this document. The safe approach is to compose established building blocks and define only the S&B-specific app, service, and policy contracts:

| Source | Relevant contribution | Boundary / S&B decision |
|---|---|---|
| [IEEE Std 2413 (IoT architectural framework)](https://ieeexplore.ieee.org/search/searchresult.jsp?queryText=IEEE%20Std%202413-2019) | Useful high-level IoT architecture vocabulary. | It is not an application package, service authorization, sandbox, or developer-SDK contract. IEEE Xplore's search record should be checked against the edition actually licensed or adopted before citing a clause; SB-MAP does not claim IEEE compliance. |
| [IETF RFC 8446 (TLS 1.3)](https://www.rfc-editor.org/rfc/rfc8446.html) | Standardized secure transport properties: confidentiality, integrity, and peer authentication when correctly configured. | Transport security does not decide whether an app may invoke a method or read an object. SB-MAP requires the deployed Mesh transport to authenticate the peer and protect traffic; it does not assert that current Mesh streams implement TLS. |
| [IETF RFC 9420 (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html) | Group membership key updates and cryptographic removal from a group. | The RFC explicitly leaves authorization to evict members to an application layer. MLS is optional for group end-to-end confidentiality and is not the app authorization or RPC protocol. |
| [IETF RFC 8707 (OAuth 2.0 Resource Indicators)](https://www.rfc-editor.org/rfc/rfc8707.html) | Separates a token's intended resource audience from its access scope. | SB-MAP applies the same resource-binding principle to Mesh grants; it does not require an OAuth deployment. |
| [SPIFFE overview](https://spiffe.io/docs/latest/spiffe-about/overview/) | Workload identity and short-lived cryptographic identities across dynamic environments. | A service identity should be distinct from the hosting node identity. SPIFFE/SPIRE could be an implementation option, not an unconditional runtime dependency. |
| [WASI security model](https://wasi.dev/security) and [Component Model](https://component-model.bytecodealliance.org/) | Capability-oriented sandbox interfaces for WebAssembly modules/components. | WASI is not a WebView, but it creates another runtime and trust boundary. It is not the native desktop UI model. Consider it later for optional third-party plugins after supported WASI versions and runtime hardening are selected. |
| [IETF RFC 9124](https://www.rfc-editor.org/rfc/rfc9124.html) | A manifest and threat-model approach for firmware updates. | Useful as a supply-chain design reference, but it is firmware-specific and is not adopted as the SB-MAP package format. |

IEEE's useful role here is architectural context, not a ready-made Mesh app protocol. The proposal uses IETF-style normative language and makes the S&B-specific service and permission boundaries explicit.

## 3. Application model

An SB-MAP application has three independently controlled parts:

1. **Client:** native Rust UI, commonly hosted by `sb-desktop`; installed and sandboxed locally.
2. **Service:** versioned API implementation hosted by one or more authorized Mesh nodes.
3. **Optional plugin:** a separately declared, narrowly permissioned component. The initial profile does not execute third-party plugins.

The app identifier, service identifier, artifact version, API version, and Mesh identity are distinct identifiers. A node's presence in discovery does not imply that its services are trusted. A publisher signature proves that a particular key signed bytes; a configured trust policy maps that key to an authorized publisher. Neither the signature nor that mapping grants installation approval or data access.

### 3.1 Trust boundaries

- The local desktop shell mediates app installation, user consent, local sandboxing, and access to the local identity.
- Mesh discovery returns metadata and candidate service identities only.
- The authenticated Mesh transport binds a connection to a peer identity. The service independently checks active membership, grant validity, policy, and resource ACL for every operation.
- The application service executes with its own service identity and least-privilege host policy; it does not inherit blanket node-admin or user permissions.
- A publisher, service operator, Mesh administrator, and end user are separate authorities. Their approvals MUST NOT be conflated.

## 4. Package and manifest profile

An app package is an immutable bundle referenced by content digest. It includes a manifest, signed client artifact(s), service API declarations, and optional non-executable resources. Service binaries are published as independently addressable artifacts so that the service operator can approve and deploy them separately from desktop clients.

The first implementation SHOULD reuse the repository's existing release-manifest and strict Ed25519 verification mechanisms where their trust roots and semantics fit. A Mesh publisher key MUST be explicitly trusted or delegated by local/Mesh policy. It MUST NOT silently inherit trust from a Mesh catalog, transport peer, or the existing production release key.

The manifest is signed as exact bytes; verifiers MUST check the detached signature over the exact stored bytes before interpreting fields. The verifier MUST reject unsupported schema versions, invalid signatures, duplicate/ambiguous artifact identities, malformed digests, incompatible targets, and undeclared capabilities. Signature validity alone is not authorization to install or run.

Minimum manifest fields:

```json
{
  "schema_version": 1,
  "app_id": "org.skullsandbones.notes",
  "version": "0.1.0",
  "publisher_key_id": "publisher-key-1",
  "client": {
    "target": "windows-x86_64",
    "artifact": "sha256:<64 lowercase hex characters>"
  },
  "services": [{
    "service_id": "org.skullsandbones.notes.api",
    "api_version": 1,
    "contract_digest": "sha256:<64 lowercase hex characters>"
  }],
  "requested_capabilities": [
    "mesh.service:org.skullsandbones.notes.api/read"
  ],
  "sandbox_profile": "native-client-default"
}
```

This is an illustrative shape, not a finalized wire schema. Before implementation, select a canonical schema/serialization format and add committed positive and negative fixtures. The schema MUST encode all authority-bearing values explicitly; it MUST NOT accept ambient filesystem paths, arbitrary network destinations, shell commands, or implicit privilege escalation.

## 5. Discovery, invocation, and error behavior

Discovery resolves a stable service identifier to metadata, API versions, an authenticated service identity, and one or more current candidate nodes. Discovery data is untrusted until its peer identity is authenticated. The client MUST verify that the authenticated remote service identity matches the discovered service identity and expected Mesh before sending credentials.

An invocation binds all of the following:

- Mesh ID and authenticated subject device/node identity;
- service ID as the token audience;
- app ID and client artifact digest;
- API version and method;
- explicit resource/object identifiers and requested operation;
- policy or membership epoch, expiry, and a unique grant identifier;
- request ID, deadline, and idempotency key for mutating operations.

The service MUST validate the current active membership and resource ACL on each call. It MUST reject an expired grant, wrong audience, wrong Mesh, wrong subject, stale policy/membership epoch, undeclared method, resource mismatch, replayed mutation, and excessive payload. A revocation MUST prevent subsequent calls; long-lived streams MUST re-check authorization before each operation or be closed when the relevant membership/grant is revoked. Discovery, peer status, port reachability, a valid signature, or possession of a service address is never a substitute for authorization.

The current port-scoped `CapabilityToken` is not sufficient by itself for this app contract: it does not bind a grant to an app, service audience, API method, resource identifier, or policy epoch. F1-3 must introduce or adapt a versioned operation-level grant before calling this profile implemented. Do not silently widen the existing token's meaning.

Requests and responses use typed, versioned contracts. The initial Rust SDK may serialize these contracts over the existing authenticated Mesh stream, but it MUST keep transport framing separate from API schema. The current local JSON-RPC daemon API remains a local IPC contract; it is not automatically the wire protocol for remote Mesh services. Errors MUST be explicit and stable enough for clients to distinguish at least: unauthenticated, unauthorized, not found, stale/revoked grant, unsupported API version, invalid request, quota exceeded, unavailable, and internal failure. Authorization failures MUST NOT return success-shaped fallbacks.

## 6. Developer library and tools

The first SDK should be Rust-first, asynchronous, and typed:

- `sb-app-sdk`: service identifiers, typed request/response traits, authenticated `RequestContext`, cancellation/deadlines, bounded payload helpers, explicit errors, and a client that can invoke only declared services/resources.
- `sb-app-contract`: versioned contract types and test fixtures shared by service and client.
- `sb app new`, `sb app check`, `sb app package`, `sb app publish`, and `sb app install`: scaffold, validate manifest/capability declarations, package, publish signed artifacts, and install only after policy approval.
- A local test harness should simulate discovery, authenticated identities, ACL allow/deny, revocation, incompatible versions, oversized payloads, retries, and maliciously malformed manifests.

Applications SHOULD define business APIs as Rust traits with generated or shared typed wire representations. SDK methods MUST accept explicit resource handles and operation scopes rather than exposing unrestricted raw mesh sockets as an authorization shortcut. The SDK MUST NOT hold publisher private keys or let app code bypass the desktop's installation/consent boundary.

Illustrative API shape (not existing compilable code):

```rust
trait NotesService {
    async fn list(
        context: RequestContext,
        collection: ReadableCollection,
    ) -> Result<Vec<NoteSummary>, AppServiceError>;
}
```

`ReadableCollection` is a host-constructed, authorized handle, not a free-form path. The server still revalidates the current ACL; a typed client handle is not a security proof.

## 7. Runtime, sandbox, and update policy

- Desktop client binaries are local native Rust applications. Each platform MUST use an OS-enforced sandbox profile and verify enforcement before starting app code; unsupported isolation MUST fail closed or be clearly marked unsupported.
- Mesh-hosted native service binaries MUST be signed, pinned to content digests, installed only by an authorized operator, and run under a dedicated least-privilege service identity with filesystem, network, process, and resource limits.
- The initial release MUST NOT dynamically execute remote desktop UI code, scripts, or unsigned binaries.
- A future WebAssembly Component plugin profile MAY be added for untrusted extensions. It must define the exact component/WASI versions, allowed imports/capabilities, fuel/memory/time limits, host-call authorization, and conformance suite first. WASI capability isolation does not replace per-operation Mesh ACL checks.
- Updates MUST be explicit, digest-verified, signature-verified against a locally configured/delegated key, policy-approved, and protected against unauthorized rollback. A catalog update MUST NOT silently install or execute code.

This profile does not define protection against a compromised host kernel, OS administrator, trusted signer, or a service that is itself authorized to disclose data. Those residual risks must be stated in the deployment threat model.

## 8. Conformance levels and acceptance tests

**SB-MAP Client v1** MUST verify the package and signer policy, request user/administrator approval for installation, enforce its local sandbox before app startup, and use the SDK to discover and invoke typed services without treating discovery as authorization.

**SB-MAP Service v1** MUST authenticate the caller, bind the call to Mesh/service/method/resource, check fresh membership and ACL on every operation, enforce quotas/deadlines, emit explicit errors, and test revocation on an established stream.

**SB-MAP Operator v1** MUST control publisher trust roots, service placement, service identities, grants, revocation, approved versions, and audit retention independently.

A release candidate is conformant only when automated tests prove:

1. Valid signed artifacts from an untrusted publisher are rejected; trusted signer artifacts with modified bytes are rejected.
2. Discovery of an unauthorized service cannot invoke it; a peer cannot substitute a different service or Mesh identity.
3. Wrong audience, method, resource, subject, expired/stale grant, inactive member, and revoked stream are rejected.
4. A user with access to one object cannot read another by changing a path or object ID.
5. Oversized, malformed, replayed, downgraded, and deadline-expired requests fail deterministically.
6. Untrusted app code cannot access undeclared files, network destinations, processes, secrets, or host capabilities.
7. Install/update rollback, signer rotation, denial, and recovery are tested on each declared platform.

## 9. Implementation sequence for this repository

**Implementation note (2026-10-18):** `tools/sb-app-contract` provides strict signed-manifest verification, explicit publisher trust, typed operation grants, and a verifier binding grants to verified app declarations. `tools/sb-app-protocol` provides bounded version-1 JSON control frames, a typed operation request, and ordered size-/digest-checked binary chunk transfer primitives. Neither crate is yet called by an authoritative Mesh service; the protocol crate does not itself provide transport confidentiality, authenticate its caller, query current RBAC/object ACL state, or create an end-to-end authorization boundary. The full conformance requirements above remain open.

1. **Protocol and product-model freeze:** confirm `sb-desktop` as the always-local Mesh Client and policy broker; keep optional native app clients separate; decide the peer transport security guarantees, canonical framing, trust-root ownership, grant lifecycle, metadata privacy, and cache/replication semantics in §10.
2. **Core contract:** define typed identifiers, manifest parsing/validation, service API version negotiation, stable errors, and shared fixtures in `sb-core` or a dedicated contract crate.
3. **Authorization:** replace/extend the port-only capability model with a versioned grant bound to service audience, method, resource/version, device subject, expiry, and current policy/membership epoch. Re-check it on every request/stream operation.
4. **Read-only P2P slice:** build catalog discovery plus an ACL-filtered `sb-drive` object read through a narrow desktop broker; test unauthorized discovery, revoked access, tampering, quotas, and cache isolation before introducing replication.
5. **Developer SDK and VCS slice:** build one minimal `sb-app-sdk` client/service, then connect optional `sb-studio` to `sb-code` authorized workspace pulls and signed, authoritative-writer/CAS commits.
6. **Artifact pipeline:** extend signing/catalog publication without trusting discovery for execution; test signer delegation, digest mismatch, downgrade, and revocation. App clients remain optional and are never bundled into the base desktop.
7. **Runtime hardening and migration:** enforce per-app OS sandbox profiles, broker permissions, and resource limits; migrate `sb-studio`/`sb-workbench` only after native feature parity and per-app release gates. `netgrid` and remote Shadow-PC display/input are outside this desktop Mesh Client profile.

Related tracked work: [F1-3 and F1-5 in the project backlog](../brain/backlog.md), [Phase 7 in the implementation plan](../brain/implementation_plan.md), and the [architecture overview](ARCHITECTURE.md). This draft adds no completed implementation and does not authorize a public Mesh deployment.

## 10. Peer-to-peer data protocol proposal

This section proposes the data-sharing profile for SB-MAP. The profile is not yet approved or complete end to end. Its bounded control-frame and chunk-transfer format is implemented in `sb-app-protocol` and used by the `sb-drive` stream v2; authorization grants, catalog discovery, broker integration, and peer replication remain open. It deliberately reuses authenticated Mesh streams and existing domain models rather than treating peer discovery, a port, or an arbitrary file path as an authorization system.

### 10.1 Roles and trust boundaries

- **`sb-desktop` Mesh Client:** local native shell, app catalog, consent UI, per-app sandbox launcher, and narrow local broker. It owns local installation state; it does not own the Mesh's authoritative data or policy.
- **App client:** an optional, separately installed native client process. It runs in its own OS-enforced sandbox and requests only declared broker operations. App processes do not receive the user's Mesh private key, unrestricted sockets, or ambient filesystem access.
- **Resource authority:** the Mesh service/node that owns the authoritative object catalog, ACL/RBAC state, or `sb-code` workspace policy. It decides whether an operation is allowed and re-checks current state for each request.
- **Data peer:** an authenticated Mesh node that may provide bytes for an exact immutable object version, or replicate an explicitly permitted VCS workspace. A data peer is not automatically the resource authority.
- **Transport peer/relay:** forwards encrypted traffic and identifies its authenticated connection peer. Forwarding, routing, relay, or successful handshakes grant no data access.
- **Publisher:** signs a client package. Publisher trust permits signature verification under local policy; it does not grant Mesh membership or access to any resource.

### 10.2 Protocol layers

The protocol has four independently enforced layers:

1. **Mesh transport:** establishes an authenticated peer identity and protects data in transit. Reuse the existing Mesh transport where its confidentiality, integrity, peer binding, replay protection, and stream lifecycle are demonstrated. An intermediary must not become trusted merely because it relays a stream. The exact transport guarantees are a release blocker to verify; this document does not claim that current streams meet every requirement.
2. **Discovery and catalog:** advertises opaque stable IDs, versions, service/API metadata, and optionally availability hints. Catalog results are hints only. Listings must be filtered by `Discover`/`List`; metadata itself may be sensitive. A client must resolve authorization at the owning service before acting.
3. **Operation authorization:** binds each operation to the authenticated subject, Mesh, app ID and client digest, service/API, operation, resource/version, current policy epoch, expiry, and request identifier. The service checks current membership and ACL/RBAC, plus the app grant, on every operation. A port-scoped token alone is insufficient.
4. **Data plane:** transfers bounded control frames and payload bytes over an authenticated stream. Data is addressed by object/version IDs and content digests, never by a caller-selected host path. Each payload is size-limited, hashed, and written to a temporary cache file; it is published to the app only after full verification.

### 10.3 Resource classes and consistency

The protocol distinguishes three resource classes; their permissions and consistency rules are not interchangeable:

| Class | Identity and transfer | Write/consistency rule |
|---|---|---|
| Signed app/package artifact | App ID, version, platform target, publisher key ID, artifact digest. Fetch from any candidate peer only if exact bytes verify against a locally approved/delegated publisher key. | Immutable and content-addressed. Installing is a separate local user/policy decision; discovery or signature validity alone never auto-installs. |
| Mesh object/blob | Stable `MeshObjectId`, immutable `ObjectVersionId`, SHA-256, byte size, media type, and an opaque provider locator. Current `sb-mesh` object ACLs already distinguish `Discover`, `List`, `Read`, `Write`, and other permissions. | New versions are created by an authorized write operation; old versions remain immutable. No implicit path traversal or mutation of a cached version. |
| `sb-code` workspace | Stable workspace ID, repository identity, signed commit/DAG IDs, policy version, authoritative writer, and allowed replica set. | Reads/pulls follow replica policy; writes go only to the authoritative writer and require a fast-forward/CAS check. Conflicts fail explicitly. Mesh object `Write` does not imply VCS commit authority. |

### 10.4 Request lifecycle

An initial read or service call follows this sequence:

1. `sb-desktop` selects the active Mesh using fresh runtime identity; it does not infer a connected Mesh from a configuration file or cached peer list.
2. The client discovers a catalog entry. The response contains identifiers and availability, not an access grant.
3. The client resolves the resource with its owner/authority. The authority authenticates the transport-bound peer identity and maps it to the current Mesh device/user principals.
4. The client presents an app invocation context and narrowly scoped operation grant. The authority checks the verified app declaration, active membership, current ACL/RBAC and policy epoch, object/version state, quota, and expiry. It returns an explicit denial or a short-lived, exact-operation transfer authorization.
5. The client opens a bounded stream for that exact resource/version. Payloads are transferred in capped chunks; the receiver verifies total size and the signed/catalog-authorized content digest before atomically publishing a local cache entry.
6. The client closes the stream on completion, timeout, revocation, protocol error, or cancellation. Long-lived sessions must reauthorize before each operation; authorization is not inherited from opening a port or an earlier stream.

**Initial wire-format decision for implementation:** control messages use strict, versioned JSON (`serde` structures reject unknown fields) with an explicit big-endian length prefix and a 64 KiB maximum frame. Payload data is not embedded in JSON: it is sent as bounded binary chunks of at most 64 KiB, with an explicit sequence number, declared total size, and per-chunk digest; receivers also check the whole-object digest. The existing 256 MiB `sb-drive` object limit is the initial object ceiling, subject to per-operation/service quotas. Signature inputs use domain-separated, length-prefixed canonical fields as in `sb-app-contract`; signatures MUST NOT depend on re-serialized JSON bytes. A future encoding requires a negotiated new protocol version, not silent replacement.

The common request envelope has an explicit protocol version, request ID, Mesh ID, subject node/device, app ID and client digest, service ID and API version, operation, opaque resource ID, optional immutable version ID, policy epoch, deadline, and grant reference. The service MUST derive the authenticated subject from the transport and reject any mismatch with fields supplied by the client. Unknown fields, unsupported versions, ambiguous identifiers, oversized frames, stale epochs, and expired deadlines fail closed with stable error classes.

**Implementation status:** `sb-app-protocol` implements strict bounded JSON control framing, transfer offers, binary chunks, and per-chunk plus whole-transfer SHA-256 validation. `sb-drive` stream v2 now sends an offer bound to the authorized object/version, then bounded chunks; the client checks request/transfer identity, order, offsets, sizes, and digests before publishing its temporary cache file. Its request still uses the legacy relative locator, and the service does not yet consume the full `OperationRequest`/grant contract. The Mesh transport security guarantee, fresh grant validation, active-stream revocation, and local sandbox broker remain release gates; this is a verified transfer slice, not a production-ready Mesh application protocol.

### 10.5 Peer-to-peer distribution without weakening ACLs

The profile separates **authorization** from **byte sourcing**:

- The resource authority decides authorization; a peer selected for transfer does not make that decision.
- **Rollout decision:** the first protected-data release fetches from the authoritative resource service only. This is the simplest safe path and matches the current `sb-drive` server-side ACL check. This is not a rejection of P2P replication; it is the prerequisite authorization baseline.
- A subsequent replication profile MAY fetch immutable chunks from other peers only after the authority issues a short-lived transfer lease scoped to the authenticated recipient, exact Mesh, object/version, whole-object digest, allowed chunk hashes/ranges, quota, and expiry. The receiving peer must validate that lease and the exact chunk hashes. A peer without current authority state must never mint or broaden a lease. Lease duration and expiry are the initial bound on revocation latency; shorter or immediate revocation requires online authority revalidation or a reliable stream-close/revocation channel and must be tested before claiming it.
- If the deployment cannot prove confidential, integrity-protected end-to-end transport to the authorized recipient, protected bytes MUST NOT be sent through an untrusted relay. Relay metadata exposure and traffic analysis remain risks even with payload encryption.
- Replication is opt-in and policy-scoped. Each replica records source/version/digest and last validation. Local caches are not ACL authorities and must be partitioned by Mesh, user/device, app, and resource. Revoking future access prevents new reads but cannot retract bytes already delivered to a peer; cache purge is best-effort and this limitation must be shown to users.
- Discovery and peer status must not reveal names, object contents, or existence to principals lacking the relevant `Discover`/`List` permission.

### 10.6 `sb-desktop` Mesh Client and optional applications

The “virtual PC in the Mesh” is a Mesh-backed workspace, not a remote desktop. `sb-desktop` is the always-local Mesh Client and policy broker. Optional app clients (initial candidates: `sb-studio` and `sb-workbench`) are not bundled by default. Users may install an app from a Mesh catalog in one click only when the package trust policy is already satisfied and the consent screen makes publisher, version, requested capabilities, sandbox profile, and local storage requirements explicit. A new publisher or increased capability set requires renewed consent.

The Mesh supplies signed package bytes and authorized data/services; it does not stream executable UI code into `sb-desktop` or start remote binaries. `sb-desktop` verifies platform target, signature, digest, version/rollback policy, and sandbox policy before atomically installing to a per-user app directory. It launches each app as a separate sandboxed process. The app's only Mesh route is a broker API whose operations are bound to the app identity and reauthorized by the remote service. Local cache, temporary data, and any user-approved working copy are separate from the authoritative Mesh resource.

Mesh application availability does not mean that every inventory product is an installable app. Libraries and background services may remain platform components; `netgrid` is outside this desktop app-catalog profile. `sb-code` remains the VCS engine/service used by the desktop workflow rather than an arbitrary executable injected into the shell. `sb-studio` is the first optional app candidate and should provide the first end-to-end workspace slice.

### 10.7 Open protocol decisions and acceptance gates

Before freezing a protocol version, maintainers must decide:

- exact guarantees and threat model of the authenticated Mesh stream, including confidentiality, replay, and relay behavior;
- stable service/resource ID namespaces and policy-epoch authority;
- publisher trust delegation and its separation from release-signing keys;
- grant issuance, expiry, revocation, replay prevention, and recovery after offline periods;
- peer-lease duration/revocation latency, cache retention/purge behavior, and metadata visibility;
- workspace ownership, replica eligibility, commit-signing identity, and conflict/recovery policy.

The first vertical slice should be read-only: catalog discovery, `Discover`/`List` filtering, an ACL-checked `sb-drive` object read directly from its authority, bounded verified caching in the sandbox broker, and visible denial/revocation/offline states. After operation grants, active-stream reauthorization, and lease invalidation are proven, add opt-in immutable peer replication. The second application slice should connect optional `sb-studio` to a `sb-code` workspace, beginning with authorized pull and progressing to signed commits through authoritative-writer/CAS checks. Do not add multi-writer replication or general remote process execution to either slice.

Conformance tests must include unauthorized discovery, tampered catalog/package/chunk, mismatched transport identity, stale membership/epoch, revoked access on an existing stream, wrong object/version, cross-Mesh cache collision, symlink/path substitution, quota exhaustion, offline/stale state, unauthorized replica, non-fast-forward push, duplicate/replayed mutation, and package rollback. The Shadow-PC remote-screen/input feature is out of scope: it should be removed rather than treated as the Mesh workspace UI.
