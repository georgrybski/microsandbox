//! Shared state between the NetWorker thread, smoltcp poll thread, and tokio
//! proxy tasks.
//!
//! All inter-thread communication flows through [`SharedState`], which holds
//! lock-free frame queues and cross-platform [`WakePipe`] notifications.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use microsandbox_utils::ttl_reverse_index::TtlReverseIndex;
pub use microsandbox_utils::wake_pipe::WakePipe;
use parking_lot::RwLock;

use crate::addr::normalize_ip_addr;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default frame queue capacity. Matches libkrun's virtio queue size.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Evasion audits logged before sampling starts: the first few audits
/// always emit so early diagnostics are never lost.
pub const EVASION_AUDIT_LOG_FIRST: u64 = 3;

/// Sampling stride after the first audits: log every Nth evasion audit.
///
/// The counter itself stays exact; only the log line is sampled so a
/// banner-less scanner cannot flood host logs.
pub const EVASION_AUDIT_LOG_EVERY: u64 = 100;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// All shared state between the three threads:
///
/// - **NetWorker** (libkrun) — pushes guest frames to `tx_ring`, pops
///   response frames from `rx_ring`.
/// - **smoltcp poll thread** — pops from `tx_ring`, processes through smoltcp,
///   pushes responses to `rx_ring`.
/// - **tokio proxy tasks** — relay data between smoltcp sockets and real
///   network connections.
///
/// Queue naming follows the **guest's perspective** (matching libkrun's
/// convention): `tx_ring` = "transmit from guest", `rx_ring` = "receive at
/// guest".
pub struct SharedState {
    /// Frames from guest → smoltcp (NetWorker writes, smoltcp reads).
    pub tx_ring: ArrayQueue<Vec<u8>>,

    /// Frames from smoltcp → guest (smoltcp writes, NetWorker reads).
    pub rx_ring: ArrayQueue<Vec<u8>>,

    /// Wakes NetWorker: "rx_ring has frames for the guest."
    /// Written by `SmoltcpDevice::transmit()`. Read end polled by NetWorker's
    /// epoll loop.
    pub rx_wake: WakePipe,

    /// Wakes smoltcp poll thread: "tx_ring has frames from the guest."
    /// Written by `SmoltcpBackend::write_frame()`. Read end polled by the
    /// poll loop.
    pub tx_wake: WakePipe,

    /// Wakes smoltcp poll thread: "proxy task has data to write to a smoltcp
    /// socket." Written by proxy tasks via channels. Read end polled by the
    /// poll loop.
    pub proxy_wake: WakePipe,

    /// Optional host-side termination hook used for fatal policy violations.
    termination_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,

    /// Resolved hostname index used to map destination IPs back to queried hostnames.
    resolved_hostnames: RwLock<TtlReverseIndex<ResolvedHostnameKey, IpAddr>>,

    /// Per-sandbox gateway IPv4. Set once at boot; used by
    /// `DestinationGroup::Host` rule matching and `host.microsandbox.internal`
    /// DNS synthesis. `None` in isolated unit tests.
    gateway_ipv4: OnceLock<Ipv4Addr>,

    /// Per-sandbox gateway IPv6. Set once at boot. See `gateway_ipv4`.
    gateway_ipv6: OnceLock<Ipv6Addr>,

    /// Aggregate network byte counters at the guest/runtime boundary.
    metrics: NetworkMetrics,

    /// Evasion-signal audits: SSH first flights still undecided when the
    /// peek budget expires and falling through to the generic egress
    /// verdict instead of stalling the connection. The counter is exact;
    /// the log line is sampled via [`should_log_evasion_audit`].
    evasion_audits: AtomicU64,
}

/// Aggregate network byte counters shared with the runtime metrics sampler.
pub struct NetworkMetrics {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

/// Address family for resolved hostname entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedHostnameFamily {
    Ipv4,
    Ipv6,
}

/// Composite cache key for a single DNS resolution.
///
/// `family` partitions entries so that `A` and `AAAA` responses for the
/// same hostname refresh independently instead of overwriting each other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ResolvedHostnameKey {
    hostname: String,
    family: ResolvedHostnameFamily,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SharedState {
    /// Create shared state with the given queue capacity.
    pub fn new(queue_capacity: usize) -> Self {
        Self {
            tx_ring: ArrayQueue::new(queue_capacity),
            rx_ring: ArrayQueue::new(queue_capacity),
            rx_wake: WakePipe::new(),
            tx_wake: WakePipe::new(),
            proxy_wake: WakePipe::new(),
            termination_hook: Mutex::new(None),
            resolved_hostnames: RwLock::new(TtlReverseIndex::default()),
            gateway_ipv4: OnceLock::new(),
            gateway_ipv6: OnceLock::new(),
            metrics: NetworkMetrics::default(),
            evasion_audits: AtomicU64::new(0),
        }
    }

    /// Set the per-sandbox gateway IPs. Called once at boot. Each family is
    /// only published when active for this sandbox.
    pub fn set_gateway_ips(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        if let Some(ipv4) = ipv4 {
            let _ = self.gateway_ipv4.set(ipv4);
        }
        if let Some(ipv6) = ipv6 {
            let _ = self.gateway_ipv6.set(ipv6);
        }
    }

    /// Gateway IPv4 address, if set.
    pub fn gateway_ipv4(&self) -> Option<Ipv4Addr> {
        self.gateway_ipv4.get().copied()
    }

    /// Gateway IPv6 address, if set.
    pub fn gateway_ipv6(&self) -> Option<Ipv6Addr> {
        self.gateway_ipv6.get().copied()
    }

    /// Install a host-side termination hook.
    pub fn set_termination_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self.termination_hook.lock().unwrap() = Some(hook);
    }

    /// Trigger host-side termination if a hook is installed.
    pub fn trigger_termination(&self) {
        let hook = self.termination_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Replace the resolved addresses for a hostname within the given address family.
    pub fn cache_resolved_hostname(
        &self,
        domain: &str,
        family: ResolvedHostnameFamily,
        addrs: impl IntoIterator<Item = IpAddr>,
        ttl: Duration,
    ) {
        let hostname = normalize_hostname(domain);
        let key = ResolvedHostnameKey { hostname, family };
        let addrs = addrs.into_iter().map(normalize_ip_addr);
        self.resolved_hostnames
            .write()
            .insert(key, addrs, ttl, Instant::now());
    }

    /// Clear the resolved addresses for a hostname within the given address family.
    pub fn clear_resolved_hostname(&self, domain: &str, family: ResolvedHostnameFamily) {
        let hostname = normalize_hostname(domain);
        let key = ResolvedHostnameKey { hostname, family };
        self.resolved_hostnames.write().remove(&key, Instant::now());
    }

    /// Returns `true` when any resolved hostname for `addr` satisfies `predicate`.
    pub fn any_resolved_hostname(
        &self,
        addr: IpAddr,
        mut predicate: impl FnMut(&str) -> bool,
    ) -> bool {
        let addr = normalize_ip_addr(addr);

        self.resolved_hostnames
            .read()
            .member_matches(&addr, Instant::now(), |key| predicate(&key.hostname))
    }

    /// Best-effort representative hostname previously resolved to `addr`.
    ///
    /// Returns the lexicographically smallest live hostname so SSH flow
    /// attribution is deterministic when several names share an IP (for
    /// example a shared CDN address). `None` means no cached binding;
    /// callers fall back to the stringified destination IP.
    pub fn preferred_hostname_for_ip(&self, addr: IpAddr) -> Option<String> {
        let addr = normalize_ip_addr(addr);
        let mut names: Vec<String> = self
            .resolved_hostnames
            .read()
            .keys_for_member(&addr, Instant::now())
            .into_iter()
            .map(|key| key.hostname)
            .collect();
        names.sort();
        names.into_iter().next()
    }

    /// Best-effort expiry maintenance for resolved hostnames.
    ///
    /// This runs outside the hot egress read path. If the index is currently
    /// busy, cleanup is skipped and retried on the next maintenance pass.
    pub fn cleanup_resolved_hostnames(&self) {
        if let Some(mut idx) = self.resolved_hostnames.try_write() {
            idx.evict_expired(Instant::now());
        }
    }

    /// Increment the guest -> runtime byte counter.
    pub fn add_tx_bytes(&self, bytes: usize) {
        self.metrics
            .tx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Increment the runtime -> guest byte counter.
    pub fn add_rx_bytes(&self, bytes: usize) {
        self.metrics
            .rx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Push a runtime -> guest ethernet frame and update RX metrics on success.
    pub(crate) fn push_rx_frame(&self, frame: Vec<u8>) -> bool {
        let frame_len = frame.len();
        if self.rx_ring.push(frame).is_err() {
            return false;
        }

        self.add_rx_bytes(frame_len);
        true
    }

    /// Push a runtime -> guest ethernet frame, update RX metrics, and wake libkrun.
    pub(crate) fn push_rx_frame_and_wake(&self, frame: Vec<u8>) -> bool {
        if !self.push_rx_frame(frame) {
            return false;
        }

        self.rx_wake.wake();
        true
    }

    /// Total bytes transmitted by the guest into the runtime.
    pub fn tx_bytes(&self) -> u64 {
        self.metrics.tx_bytes.load(Ordering::Relaxed)
    }

    /// Total bytes delivered by the runtime to the guest.
    pub fn rx_bytes(&self) -> u64 {
        self.metrics.rx_bytes.load(Ordering::Relaxed)
    }

    /// Record one evasion-signal audit (SSH banner undecided after budget).
    ///
    /// Returns the previous total so the caller can sample its log line
    /// with [`should_log_evasion_audit`] without extra synchronization.
    pub fn record_evasion_audit(&self) -> u64 {
        self.evasion_audits.fetch_add(1, Ordering::Relaxed)
    }

    /// Total evasion-signal audits recorded.
    pub fn evasion_audits(&self) -> u64 {
        self.evasion_audits.load(Ordering::Relaxed)
    }
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether the evasion audit recorded after `previous` prior audits
/// should emit its log line: the first few always do, then every
/// [`EVASION_AUDIT_LOG_EVERY`]th. Pure over the count, so the sampling
/// boundary is unit-testable without clocks or threads.
pub fn should_log_evasion_audit(previous: u64) -> bool {
    previous < EVASION_AUDIT_LOG_FIRST || (previous + 1).is_multiple_of(EVASION_AUDIT_LOG_EVERY)
}

pub(crate) fn normalize_hostname(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_state_queue_push_pop() {
        let state = SharedState::new(4);

        // Push frames to tx_ring.
        state.tx_ring.push(vec![1, 2, 3]).unwrap();
        state.tx_ring.push(vec![4, 5, 6]).unwrap();

        // Pop in FIFO order.
        assert_eq!(state.tx_ring.pop(), Some(vec![1, 2, 3]));
        assert_eq!(state.tx_ring.pop(), Some(vec![4, 5, 6]));
        assert_eq!(state.tx_ring.pop(), None);
    }

    #[test]
    fn shared_state_queue_full() {
        let state = SharedState::new(2);

        state.rx_ring.push(vec![1]).unwrap();
        state.rx_ring.push(vec![2]).unwrap();
        // Queue is full — push returns the frame back.
        assert!(state.rx_ring.push(vec![3]).is_err());
    }

    #[test]
    fn push_rx_frame_counts_only_successful_pushes() {
        let state = SharedState::new(1);

        assert!(state.push_rx_frame(vec![1, 2, 3]));
        assert_eq!(state.rx_bytes(), 3);

        assert!(!state.push_rx_frame(vec![4, 5]));
        assert_eq!(state.rx_bytes(), 3);
    }

    #[test]
    fn resolved_hostnames_are_isolated_per_family() {
        let state = SharedState::new(4);
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();

        state.cache_resolved_hostname(
            "Example.com.",
            ResolvedHostnameFamily::Ipv4,
            [v4],
            Duration::from_secs(30),
        );
        state.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv6,
            [v6],
            Duration::from_secs(30),
        );

        assert!(state.any_resolved_hostname(v4, |h| h == "example.com"));
        assert!(state.any_resolved_hostname(v6, |h| h == "example.com"));
        assert!(!state.any_resolved_hostname(v4, |h| h == "other.example"));
    }

    #[test]
    fn resolved_hostnames_normalize_ipv4_mapped_ipv6() {
        let state = SharedState::new(4);
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        let embedded: IpAddr = "169.254.169.254".parse().unwrap();

        state.cache_resolved_hostname(
            "metadata.example",
            ResolvedHostnameFamily::Ipv6,
            [mapped],
            Duration::from_secs(30),
        );

        assert!(state.any_resolved_hostname(embedded, |h| h == "metadata.example"));
        assert!(state.any_resolved_hostname(mapped, |h| h == "metadata.example"));
    }

    #[test]
    fn evasion_audit_counter_returns_previous_and_stays_exact() {
        let state = SharedState::new(4);
        assert_eq!(state.evasion_audits(), 0);
        assert_eq!(state.record_evasion_audit(), 0);
        assert_eq!(state.record_evasion_audit(), 1);
        assert_eq!(state.evasion_audits(), 2);
    }

    #[test]
    fn evasion_audit_log_samples_first_then_every_nth() {
        // The first audits always log.
        for previous in 0..EVASION_AUDIT_LOG_FIRST {
            assert!(should_log_evasion_audit(previous), "audit {previous} logs");
        }
        // Then silence until the Nth audit closes the stride.
        assert!(!should_log_evasion_audit(EVASION_AUDIT_LOG_FIRST));
        assert!(!should_log_evasion_audit(EVASION_AUDIT_LOG_EVERY - 2));
        assert!(should_log_evasion_audit(EVASION_AUDIT_LOG_EVERY - 1));
        assert!(!should_log_evasion_audit(EVASION_AUDIT_LOG_EVERY));
        assert!(should_log_evasion_audit(2 * EVASION_AUDIT_LOG_EVERY - 1));
    }
}
