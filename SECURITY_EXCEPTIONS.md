# Dependency Security Exceptions

DemonClaw keeps one canonical cargo-audit policy in `.cargo/audit.toml`. An advisory may be ignored only when this file contains a current justification and an explicit removal condition.

## RUSTSEC-2023-0071: Marvin Attack against the `rsa` crate

Status: accepted for the 1.0 release line as an unreachable lockfile dependency.

The committed lockfile contains `rsa 0.9.10` through SQLx's optional MySQL dependency graph. DemonClaw configures SQLx with `default-features = false` and enables PostgreSQL support only. The application does not enable SQLx MySQL support and does not call the `rsa` crate directly.

The security workflow verifies that `rsa` is absent from Cargo's active normal, build, and development dependency tree. `cargo audit` still evaluates the complete lockfile, so the advisory remains listed in `.cargo/audit.toml` until one of the removal conditions below is met.

Removal conditions:

- the `rsa` project publishes a patched release and the dependency graph can resolve to it
- SQLx removes the affected dependency from its optional graph
- DemonClaw enables MySQL or another feature that makes `rsa` reachable, in which case the build must fail until the advisory is remediated
- the lockfile no longer contains `rsa`

Review trigger: any change to SQLx features, database backends, cryptographic dependencies, or the cargo-audit advisory database.
