# SSH custody broker

The broker terminates the guest SSH session and opens a separate, host-key-pinned
upstream SSH session. It does not splice a second handshake into an existing SSH
byte stream. The host routing layer must choose broker dispatch before opening a
direct upstream connection or returning an upstream banner.

The guest-requested username must exactly match the provisioned upstream user,
including case. A username is not a workload identity. The current handler
accepts a guest public-key proof only within the supplied session context; the
guest key is not the upstream credential. The broker does not dial upstream until
that proof succeeds, then verifies the upstream host key before using its custody
key. Password authentication, implicit username remapping and fallback to direct
egress are not supported.

## Validation

```sh
nix build .#checks.x86_64-linux.ssh-termination
cargo test --locked --offline -p microsandbox-brokerd --lib --test divert_e2e
cargo test --locked --offline -p microsandbox-brokerd --test ssh_openssh -- --ignored
```

The OpenSSH tests use disposable keys, a loopback upstream and strict host-key
checks. They verify output, stderr and exit status across both SSH sessions.
Wrong guest username, guest host-trust rejection and an unsigned public-key
offer must cause zero upstream dials. A wrong upstream host key must cause zero
upstream authentication attempts. The Nix check supplies OpenSSH and explicitly
runs these tests; a normal Cargo run otherwise ignores this external-tool suite.

## Integration limits

These tests do not establish VM or nested-workload acceptance. The current
bootstrap still supplies one custody key and one instance epoch, the divert
prelude's timestamp is not a launch generation, and the default guest-facing
host key is ephemeral rather than a managed host certificate. Shared-instance
policy installation, generation-bound transport attribution, certificate trust
provisioning and automatic VM lifecycle integration need separate validation.
The framing tests alone do not exercise SSH termination.
