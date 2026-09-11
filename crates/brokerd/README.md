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

These legacy-path tests do not establish VM or nested-workload acceptance. The
legacy bootstrap supplies one custody key and one instance epoch, the divert
prelude's timestamp is not a launch generation, and the default guest-facing
host key is ephemeral rather than a managed host certificate. Shared-instance
policy installation and managed service behavior are covered by separate tests
below; generation-bound host transport attribution, certificate provisioning
and automatic VM lifecycle integration still need deployment validation.
The framing tests alone do not exercise SSH termination.

## Managed policy core

`Broker::new_managed` owns an initially closed, bounded applied-policy store and
requires an explicitly supplied guest-facing SSH host identity. It does not
read the agent console. The legacy console runner and timestamp-only divert
path refuse managed mode; neither is silently upgraded into launch authority.

The store accepts material-ready complete credential records scoped to an exact
launch, revision and effective policy/key/trust identity. Each record retains
its catalog/material reference, custody, destination, port, username and
violation policy. This initial internal projection supports exact destinations
only and refuses wildcard patterns; it does not replace the host compiler or
interpret a resolved IP as proof of an original hostname. Ambiguous matching
records refuse before admission. Private keys are non-serializable and Debug
output is redacted.

Replacing or revoking policy closes new admission immediately and signals only
the affected relays. It remains pending until their owner explicitly reports
joined SSH cleanup. Dropping an admission or setting its termination flag is
not completion. Controller loss or broker state loss invalidates the entire
management connection and cancels every relay; a new authenticated connection
must reapply current verified launches. Old fences cannot reinstall policy.

`spawn_managed_relay` reserves ownership before the guest handshake, then
rechecks the current policy at unsigned offer and signed authentication. Only
the signed request can select custody material and start upstream setup. The
owned task joins the native guest session, upstream client and channel pumps
before retiring admission. Dropping its caller-facing handle requests
cancellation without aborting the independent cleanup owner. A hidden native
handshake task whose completion cannot be observed leaves retirement pending;
closing its I/O is not substituted for a join.

The library tests exercise real SSH over private in-memory streams, including
binary output, stderr, exit status, ordinary disconnect, revocation, strict pin
refusal, wrong-user zero upstream effects and pre-authentication state loss.
They do not exercise real host-listen sockets or a multi-workload VM deployment.

The compiled scanner library belongs to the same effective stored transaction,
not an arbitrary per-relay input. Installation verifies the SHA-256 digest over
actual key, independent trust and pattern bytes before parsing or compilation.
Unsupported scanner inputs refuse before policy changes. Current plus pending
policies share limits of 4096 credentials, 4096 compiled patterns and 16 MiB
authored pattern bytes; the byte limit does not claim to measure all matcher
overhead. Managed sessions retain at most 16 unjoined channel pumps and join
finished pumps before admitting replacements. Legacy channel policy is unchanged.

## Ordinary managed service

```sh
brokerd service --credentials-directory /run/credentials/broker.service \
  --host-principal broker.example --management-port 3024 \
  --divert-port 3022 --egress-port 3023
```

`brokerd service --help` is nonbinding and does not read credentials, open the
console, initialize guest filesystems, configure networking or contact a peer.
The no-argument legacy PID 1 mode remains separate; service arguments never
fall back to it.

Supply the explicit systemd credentials directory with `host-key`,
`host-certificate` and `host-ca.pub`. The broker receives only its own Ed25519
private key, matching signed host certificate and CA public key. The CA private
key stays with the host owner. Startup checks bounded regular credential files,
private key permissions, distinct CA/host keys, trusted CA signature, host type,
current validity, an exact sole lowercase DNS principal and no critical options
before binding either listener. Missing or raw-only identity has no fallback.

russh can advertise the paired raw host-key algorithm. Managed clients must
require `HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com`, the stable broker
`HostKeyAlias`, its CA pin and `StrictHostKeyChecking=yes` only for broker-bound
destinations. Independent upstream key verification is a different check and
remains mandatory regardless of the guest client's chosen trust configuration.

The host must separately provision protected host-listen routes and verify the
original launch and destination before forwarding a managed diversion header.
The guest listener additionally requires the kernel HOST CID; header fields are
not credentials. Explicit peer denial does not stop other admitted workloads.
The direct management protocol is separate from agentd and carries a complete
policy transaction, not an exec command or a bootstrap-key update.

The authenticated owner sends `Probe` every 10 seconds to renew a 30-second
absolute lease. Only a current-fence probe renews it; a successful probe does
not mean any policy is Applied. Idle, partial-frame, write and parsing delays
cannot indefinitely extend the lease. Expiry, connection loss or local state
loss fences all admission and cancels owned relays. Reconnection requires a new
broker-issued Welcome and full desired policy reapplication. Cleanup reports
incomplete native retirement separately from its original connection failure.

Managed audit uses the admitted full launch, generation, policy revision/digest
and management fence, not fabricated CID/epoch values. The existing synchronous
audit sink is not a nonblocking or backpressure-complete logging service.

Additional native fixture commands are:

```sh
cargo test --locked --offline -p microsandbox-protocol --lib
cargo test --locked --offline -p microsandbox-brokerd --lib --test managed_openssh -- --include-ignored
```

These are disposable native file, in-memory and loopback tests, not proof of
protected host-route provisioning, ordinary guest activation or VM deployment.
End-to-end host owner reconciliation and certificate provisioning remain
separate integration responsibilities.
