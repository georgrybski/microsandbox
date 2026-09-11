//! DLP audit records for relayed SSH sessions.
//!
//! One record per pattern hit carries session identity (`cid`, `epoch`),
//! the channel number, the traffic direction, the credential name where
//! resolvable via the pattern id, the pattern id and hit digest, and the
//! applied action. Records render as single `brokerd: dlp ...` log lines
//! through the existing `eprintln!` idiom. They never carry secret content:
//! every field is an identifier, a counter, or a truncated hash.

use std::fmt;

use microsandbox_scan::{ActionSet, PatternDigest, PatternId};

use crate::policy::RelayContext;
use crate::prelude::SessionIdentity;
use microsandbox_protocol::broker::Id;

/// Audit coordinates follow the admitted transport mode. Managed launches do
/// not invent CID/epoch values from their unrelated logical identities.
pub(crate) enum AuditIdentity {
    Legacy(SessionIdentity),
    Managed(RelayContext),
}

impl AuditIdentity {
    pub(crate) fn emit(
        &self,
        channel: u32,
        direction: ChannelDirection,
        credential_id: Option<String>,
        pattern_id: PatternId,
        digest: PatternDigest,
        action: ActionSet,
    ) {
        eprintln!(
            "brokerd: dlp {}",
            self.render(
                channel,
                direction,
                credential_id,
                pattern_id,
                digest,
                action
            )
        );
    }

    fn render(
        &self,
        channel: u32,
        direction: ChannelDirection,
        credential_id: Option<String>,
        pattern_id: PatternId,
        digest: PatternDigest,
        action: ActionSet,
    ) -> String {
        match self {
            Self::Legacy(identity) => AuditRecord::new(
                *identity,
                channel,
                direction,
                credential_id,
                pattern_id,
                digest,
                action,
            )
            .render(),
            Self::Managed(context) => {
                let session = context.fence.session();
                format!(
                    "broker={} controller={} connection={} launch={:?} generation={} revision={} policy={} channel={} direction={} credential={:?} pattern={} digest={} action={}",
                    session.broker.to_hex(),
                    session.controller.to_hex(),
                    session.connection,
                    context.launch.instance,
                    Id::from_bytes(context.launch.generation)
                        .expect("admitted generation")
                        .to_hex(),
                    context.revision,
                    Id::from_bytes(context.digest)
                        .expect("admitted policy")
                        .to_hex(),
                    channel,
                    direction,
                    credential_id.as_deref().unwrap_or("-"),
                    pattern_id,
                    digest,
                    action
                )
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Traffic direction of a scanned chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDirection {
    /// Guest to upstream (channel data, extended data, exec commands).
    GuestToUpstream,

    /// Upstream to guest (relayed channel data and extended data).
    UpstreamToGuest,
}

/// One DLP audit record: identities and hashes only, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Sandbox transport identifier from the validated prelude.
    pub cid: u64,

    /// Divert epoch from the validated prelude.
    pub epoch: u64,

    /// SSH channel number the hit was observed on.
    pub channel: u32,

    /// Traffic direction of the scanned chunk.
    pub direction: ChannelDirection,

    /// Credential name resolved via the pattern id, when resolvable.
    pub credential_id: Option<String>,

    /// Which pattern matched.
    pub pattern_id: PatternId,

    /// Hit-time digest over the pattern's raw bytes.
    pub digest: PatternDigest,

    /// Reduced action applied to the hit.
    pub action: ActionSet,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AuditRecord {
    /// Build a record from session identity and hit attribution.
    pub fn new(
        identity: SessionIdentity,
        channel: u32,
        direction: ChannelDirection,
        credential_id: Option<String>,
        pattern_id: PatternId,
        digest: PatternDigest,
        action: ActionSet,
    ) -> Self {
        Self {
            cid: identity.cid,
            epoch: identity.epoch,
            channel,
            direction,
            credential_id,
            pattern_id,
            digest,
            action,
        }
    }

    /// Render the record as log fields (identifiers and hashes only).
    pub fn render(&self) -> String {
        format!(
            "cid={} epoch={} channel={} direction={} credential={} pattern={} digest={} action={}",
            self.cid,
            self.epoch,
            self.channel,
            self.direction,
            self.credential_id.as_deref().unwrap_or("-"),
            self.pattern_id,
            self.digest,
            self.action,
        )
    }

    /// Emit the record on the broker log.
    pub fn emit(&self) {
        eprintln!("brokerd: dlp {}", self.render());
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for ChannelDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::GuestToUpstream => "guest-to-upstream",
            Self::UpstreamToGuest => "upstream-to-guest",
        };
        f.write_str(value)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_scan::{PatternDigest, PatternId};

    #[test]
    fn managed_audit_uses_full_admitted_launch_without_legacy_coordinates() {
        use crate::policy::{Launch, PolicyStore};
        let mut store = PolicyStore::new([1; 32], 1, 1).unwrap();
        let context = RelayContext {
            fence: store.connect([2; 32]).unwrap(),
            launch: Launch {
                instance: "context/workload/instance".into(),
                generation: [3; 32],
            },
            revision: 4,
            digest: [5; 32],
            host: "git.example".into(),
            port: 22,
        };
        let source = record();
        let rendered = AuditIdentity::Managed(context).render(
            source.channel,
            source.direction,
            source.credential_id.clone(),
            source.pattern_id,
            source.digest,
            source.action,
        );
        assert!(rendered.contains("launch=\"context/workload/instance\""));
        assert!(rendered.contains(&format!("broker={}", "01".repeat(32))));
        assert!(rendered.contains(&format!("controller={}", "02".repeat(32))));
        assert!(rendered.contains("revision=4"));
        assert!(rendered.contains(&format!("generation={}", "03".repeat(32))));
        assert!(rendered.contains(&format!("policy={}", "05".repeat(32))));
        assert!(!rendered.contains("cid=") && !rendered.contains("epoch="));
        assert!(!rendered.contains("pattern-bytes-001"));
        assert_eq!(
            AuditIdentity::Legacy(identity()).render(
                source.channel,
                source.direction,
                source.credential_id.clone(),
                source.pattern_id,
                source.digest,
                source.action
            ),
            source.render()
        );
    }

    fn identity() -> SessionIdentity {
        SessionIdentity {
            cid: 7,
            epoch: 1_700_000_100,
        }
    }

    fn record() -> AuditRecord {
        AuditRecord::new(
            identity(),
            3,
            ChannelDirection::GuestToUpstream,
            Some("api-key".to_string()),
            PatternId::derive(
                "api-key",
                microsandbox_scan::Decoder::Raw,
                b"pattern-bytes-001",
            ),
            PatternDigest::of_raw(b"pattern-bytes-001"),
            ActionSet {
                enforce: Some(microsandbox_scan::Severity::BlockAndLog),
                audit: true,
                count: true,
            },
        )
    }

    #[test]
    fn audit_record_renders_identity_and_hashes() {
        let rendered = record().render();
        assert!(rendered.contains("cid=7"));
        assert!(rendered.contains("epoch=1700000100"));
        assert!(rendered.contains("channel=3"));
        assert!(rendered.contains("direction=guest-to-upstream"));
        assert!(rendered.contains("credential=api-key"));
        assert!(rendered.contains("action=block-and-log"));
    }

    #[test]
    fn audit_record_never_renders_secret_content() {
        // The rendered line carries the pattern id and digest (hashes of
        // the pattern), never the 21 pattern bytes themselves.
        let secret = b"pattern-bytes-001-very-secret-tail".to_vec();
        let record = AuditRecord::new(
            identity(),
            0,
            ChannelDirection::UpstreamToGuest,
            None,
            PatternId::derive("cred", microsandbox_scan::Decoder::Raw, &secret),
            PatternDigest::of_raw(&secret),
            ActionSet::passthrough(),
        );
        let rendered = record.render();
        assert!(!rendered.contains("very-secret-tail"));
        assert!(!rendered.contains(&hex_of(&secret)));
        assert!(rendered.contains("credential=-"));
        assert!(rendered.contains("direction=upstream-to-guest"));
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
