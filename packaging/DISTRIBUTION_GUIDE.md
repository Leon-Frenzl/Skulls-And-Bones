# Skulls & Bones (S&B) Distribution Guide

## Current installation path

The supported local bootstrap builds the launcher from an existing source
workspace. It requires Rust/Cargo, but does not invoke a Git client:

```text
cargo install --path tools/sb --bin sb
sb --help
sb status
```

This installs only the `sb` launcher. It does not install every tool or start
Mesh services. Obtain the workspace through an approved local or Mesh-based
source-transfer process before running these commands.

## Signed tool artifacts

The CLI can install tools from a signed release manifest and matching archives
when they have been published to the configured S&B release host. `sb release
pack` and `sb release sign` provide local artifact-generation commands.
Availability of a hosted manifest, signature and platform archive must be
verified by the release operator; no live hosted installation is currently
claimed.

`sb release pack-all` packages the complete set of installable products declared
for the selected target in `product-inventory.json`. It fails when even one
required binary is missing; it does not publish a partial suite archive as a
successful release. Listed release targets are intended build targets, not
evidence that cross-builds or hosted artifacts have been validated.

## Removed automation and hosting

GitHub Actions workflows, automatic GitHub Releases, repository metadata and
Git-specific hooks have been removed. There is currently no automated
multi-platform CI/release pipeline or one-click bootstrap installer. A local
build or passing test is not proof that signed artifacts are published or
available to users.

Adding a future distribution service requires an explicitly configured host,
maintained signing-key custody, platform build/test evidence, artifact
verification and a documented end-to-end installation test.

## Release security boundary

A signed manifest and archive hashes authenticate the artifacts only when the
signing key, pinned public key and verification path are correctly managed.
The inclusion of a tool in an archive does not constitute a security approval.
In particular, `sb-mesh` remains experimental and must not be advertised as a
production-ready VPN or as WireGuard compatible.
