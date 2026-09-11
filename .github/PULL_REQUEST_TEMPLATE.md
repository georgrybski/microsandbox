## Summary

<!-- What changed and why. Conventional-commit style PR title, under 72 chars. -->

## Test plan

<!-- Concrete commands and observable results. `nix flake check` is expected
     to be green (note: pure eval of the devshell needs the devenv-root
     override — see flake.nix; heavy checks clippy/unit may be validated in
     the devshell on disk-constrained hosts). -->

## Agent conventions

- Agents must not self-apply heavy/KVM CI labels.
- Commit subjects follow Conventional Commits.
- Commits are signed per AGENTS.md.
- Never `--no-verify`.
- Upstream-bound changes must contain no downstream-owned files (flake.nix, nix/, downstream workflows, DOWNSTREAM.md).
