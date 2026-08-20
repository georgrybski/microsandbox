# Mount path policy

## What it is

A mount path policy is a compiled JSON program attached to a bind mount via
the `policy=<path>` mount token (or the SDK `mount_policy(...)` builder
field). It hides, write-restricts, or protects host paths from the guest
without copying the mount. Enforcement lives in the passthrough filesystem:
the policy file is loaded once at sandbox start (relative to the sandbox's
approved runtime state directory, fail-closed on any malformed input), and
the resulting in-memory program is consulted for every guest-visible path
for the mount's lifetime.

The authoritative description of the runtime semantics — masking, write
admission, the protect tier, tags, cascade removal, and the version-1 JSON
program format — is [docs/sandboxes/volumes.mdx](docs/sandboxes/volumes.mdx),
section "Mount path policy". That page stays the single authority for what
this repository enforces; this file is only a pointer and a status note.

## The stack-level story

This repository is the runtime half of the feature. The workestrate stack
(a sibling checkout) drives it end-to-end:

- a hierarchical `[policy.mounts.read]` / `[policy.mounts.write]` TOML
  config surface spread across six scopes (home registry, user-global
  overrides, reference config, config-repo layers, workload level, mount
  entries);
- a compiler that collects those fragments and folds them — precedence,
  freeze, trust gates, conflict detection — into the version-1 program
  this repository's loader consumes;
- per-mount policy files written to `$MSB_HOME/mount-policy/<instance>/<slug>.json`;
- the loader-relative `policy=` token on the generated mount spec.

Users of that stack never write the JSON program by hand; they declare
read/write intent in TOML and the compiler emits what this repository
enforces.

## References

The following live in the sibling `workestrate` checkout (paths relative to
the checkout root):

Concept docs (`workestrate/docs/mount-policy/`):

- `00-overview.md` — what mount path policy is and how the pieces fit.
- `01-runtime-semantics.md` — visibility, write admission, protect, tags,
  cascade.
- `02-config-surface.md` — the unified TOML surface.
- `03-hierarchy-and-precedence.md` — scopes, authority order, freeze, trust
  gates.
- `04-compiler-and-wire.md` — the collect-and-compile pipeline and the
  version-1 wire program.
- `05-cookbook.md` — worked recipes.
- `06-testing.md` — verifying policy behavior (explain/preview, smoke
  checks, caveats).

Decision record:

- `workestrate/docs/migration/50-decisions/0031-mount-path-policy-config-surface.md` —
  ADR 0031, the full treatment of why the config surface was unified on the
  read/write axes and how the old vocabulary maps onto it.

## Status

- Platform support: Linux-first. On macOS the `policy=` token and the
  `mount_policy` builder field are accepted for API compatibility but
  enforcement is a no-op; on Windows the field is not supported (see
  volumes.mdx, "Platform support").
- The `write.allow` union arm landed on develop (`63c0dff0`, plus the
  authority-order review fix `808bcf45`). It activates downstream when
  consumers re-pin past `3bd051bf`; at the pinned runtime the wire format
  and the mask/protect/write-deny semantics are unchanged.
