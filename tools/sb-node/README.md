# `sb-node`

`sb-node` runs the local Mesh anchor and explicit cross-mesh service routes.

## Background daemon

```text
sb node start
sb node status
sb node stop
```

`start` launches the current `sb-node` executable detached from the terminal,
records a PID plus executable and process-instance identity under
`~/.sb-node/daemon.json`, and appends output to `~/.sb-node/daemon.log`.
`stop` only signals a process whose executable and instance identity match that
state record. The direct `sb node daemon` foreground command remains available.

## Peer services

Start the read-only drive service on a peer that hosts files, then add the
explicit source-to-target route on the anchor:

```text
sb drive serve --root <directory> --mesh <host-mesh> [--catalog <object-catalog.json>]
sb-node route add-drive --source-mesh <requesting-mesh> --target-mesh <host-mesh>
```

The anchor requires an active `stream:transfer` member grant. A route can
additionally require a capability token if that source/target rule already
uses token enforcement. The drive host also checks fresh host-mesh membership,
the authenticated peer public key/node binding, and `Read` permission for the
unique current `sb-drive` object version on every download. Its default catalog
is `~/.sb-node/catalog/<host-mesh>/object-catalog.json`; missing policy,
catalog, or ACL data denies access. The service binds only to loopback and
must be registered by `sb-node` on port `58833`.

For remote code synchronization (`sb-code`), authorize the source-to-target route on the anchor:

```text
sb-node route add-code --source-mesh <source-mesh> --target-mesh <target-mesh>
```

The route authorizes port `58832`; `stream:transfer` and `code:sync`
membership capabilities are still required.

For read-only browser access to repository history and files, start
`sb-code web --workspace <repository>` on the repository host and add a separate
viewer route:

```text
sb-node route add-code-web --source-mesh <requesting-mesh> --target-mesh dev-mesh
```

The route authorizes only port `58835`. Viewers need active `stream:transfer`
and explicit `code:view` membership capabilities; this does not grant
`code:sync`. A viewer workstation runs
`sb-code web-proxy --source-mesh <requesting-mesh> --target-mesh dev-mesh --anchor <node-address>:58888`
and opens `http://127.0.0.1:58836`. The service and proxy bind to loopback;
the browser traffic crosses the existing authenticated Cross-Mesh stream.
Restart the anchor daemon after changing routes so it reloads the policy.

For Studio AST scope locks, configure the authoritative mesh on the anchor:

```text
sb-node route add-ast-lock --mesh <studio-mesh>
```

The previous `add-ast-locks` command remains an alias. The anchor starts the
loopback-only lock authority with its daemon. Studio discovers configured
`58832` and `58834` routes from `~/.sb-mesh/cross_mesh_rules.json` and displays
their configuration state. Lock claims, releases, heartbeats, and snapshots
use the authenticated port `58834` stream. The anchor additionally requires
an active `stream:transfer` member grant. Active lock records expire after
180 seconds.
