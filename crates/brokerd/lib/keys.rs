//! Sealed key custody for the broker VM.
//!
//! Custody chain: the launcher resolves credential material host-side and
//! projects the decrypted Ed25519 seed into the typed bootstrap frame
//! ([`BrokerSshKey`]).
//! [`BrokerKey::from_bootstrap`] moves those bytes into a parsed Ed25519
//! keypair exactly once. The seed copy is zeroized after expansion, the
//! parsed scalar lives in `ssh-key`'s own zeroizing buffers, and custody
//! fails closed through [`CustodyError`]: an absent, unparsable, or
//! wrong-type key never signs. (SOPS resolution stays host-side, so the
//! `Undecryptable` layer of the source backend has no brokerd equivalent.)
//!
//! Adapted from the sealed-key backend that signs real SSHSIG structures:
//! the error taxonomy and the SSHSIG sign/verify behavior are preserved,
//! while the secret-ID/env-var resolution inputs are replaced by direct
//! bootstrap delivery.

use russh::keys::PrivateKey;
use russh::keys::ssh_key::{
    self, HashAlg, LineEnding,
    private::{Ed25519Keypair, KeypairData},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use microsandbox_protocol::bootstrap::{BROKER_KEY_TYPE_ED25519, BrokerSshKey};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Expected byte length of a provisioned Ed25519 private seed.
const ED25519_SEED_BYTES: usize = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Every way sealed-key custody can refuse.
///
/// Variants carry static failure details only — never key text — so they
/// are safe to log. The taxonomy mirrors the source backend minus its
/// host-side undecryptable layer, which cannot occur here because brokerd
/// receives decrypted material rather than SOPS configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CustodyError {
    /// The bootstrap carried no key material. Fail-closed: an absent key
    /// never signs. This is also the clean refusal when a new guest runs
    /// against an old host that predates the typed bootstrap field.
    #[error("sealed key material absent: {detail}")]
    Absent {
        /// What was missing (a field name, never a secret).
        detail: String,
    },

    /// The material is not usable key bytes (wrong seed length).
    #[error("sealed key material unparsable: {detail}")]
    Parse {
        /// Parser failure detail (lengths and tags, no key echo).
        detail: String,
    },

    /// The material names an unsupported key type. brokerd holds no
    /// passphrase path and no non-Ed25519 code path, so anything else
    /// stays closed.
    #[error("sealed key material has wrong key type: {detail}")]
    WrongType {
        /// What was found instead of a cleartext Ed25519 seed.
        detail: String,
    },
}

/// One Ed25519 keypair held in sealed custody.
///
/// Retains only the parsed keypair: construction copies the bootstrap seed
/// into [`Ed25519Keypair`] (whose scalar `ssh-key` redacts from `Debug`
/// and zeroizes on drop) and zeroizes the caller's byte vector. Dropping
/// this value drops the keypair. There is deliberately no `Clone` and no
/// `Serialize` impl: custody is handoff-only, consumed by the SSH client
/// authentication and SSHSIG signing paths in this crate.
pub struct BrokerKey {
    /// Provenance label (a field name, not a secret — safe to log, and
    /// shown by the redacting `Debug` impl).
    provenance: String,

    /// Parsed keypair. Field-private: signing goes through
    /// [`BrokerKey::sign_sshsig`] and upstream authentication through
    /// [`BrokerKey::private_key`], so no accessor can leak bytes.
    key: PrivateKey,
}

/// How SSHSIG verification can fail.
///
/// Carries no key text and no payload — only the failure class (plus static
/// parser detail), so results are safe to log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SshSigVerifyError {
    /// The armored signature or the authorized-keys public key does not
    /// parse (static `ssh-key` detail, no key echo).
    #[error("sshsig parse failed: {detail}")]
    Parse {
        /// Parser failure detail.
        detail: String,
    },

    /// The signature's embedded public key is not the given key.
    #[error("sshsig public key does not match the given key")]
    KeyMismatch,

    /// The given namespace differs from the signature's namespace. Fires
    /// before any cryptography: the namespace is checked as a string and
    /// bound into the signed preimage, so cross-namespace replay fails
    /// twice over.
    #[error("sshsig namespace does not match the given namespace")]
    NamespaceMismatch,

    /// Key and namespace match, but the Ed25519 check over the
    /// namespace-bound preimage failed (wrong payload or tampered
    /// signature).
    #[error("sshsig signature invalid for the given payload")]
    SignatureInvalid,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BrokerKey {
    /// Move bootstrap key material into sealed custody.
    ///
    /// The seed bytes are copied into a zeroizing buffer, expanded into an
    /// Ed25519 keypair, and the source vector is zeroized before return.
    /// The surrounding bootstrap frame and console input buffer still hold
    /// transient copies until brokerd drops them after startup; that
    /// teardown is best-effort process hygiene, while this move is the
    /// custody boundary.
    ///
    /// # Errors
    ///
    /// - [`CustodyError::WrongType`] when the key-type tag is not
    ///   `"ed25519"`.
    /// - [`CustodyError::Parse`] when the seed is not 32 bytes.
    pub fn from_bootstrap(mut key: BrokerSshKey) -> Result<Self, CustodyError> {
        if key.key_type != BROKER_KEY_TYPE_ED25519 {
            key.key_bytes.zeroize();
            return Err(CustodyError::WrongType {
                detail: format!(
                    "expected an `{BROKER_KEY_TYPE_ED25519}` seed, found {:?}",
                    key.key_type
                ),
            });
        }
        if key.key_bytes.len() != ED25519_SEED_BYTES {
            let len = key.key_bytes.len();
            key.key_bytes.zeroize();
            return Err(CustodyError::Parse {
                detail: format!("expected {ED25519_SEED_BYTES} seed bytes, found {len}"),
            });
        }
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_BYTES]);
        seed.copy_from_slice(&key.key_bytes);
        key.key_bytes.zeroize();
        let pair = Ed25519Keypair::from_seed(&seed);
        let private = PrivateKey::new(KeypairData::Ed25519(pair), "brokerd").map_err(|e| {
            CustodyError::Parse {
                detail: format!("expand Ed25519 seed into keypair: {e}"),
            }
        })?;
        Ok(Self {
            provenance: "bootstrap.broker_key".to_string(),
            key: private,
        })
    }

    /// Provenance label for this key (a field name, not a secret).
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// Borrow the parsed keypair for handoff-only use by the upstream SSH client.
    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.key
    }

    /// Public key as an `authorized_keys` line (log-safe diagnostics).
    pub fn public_key_openssh(&self) -> String {
        self.key.public_key().to_openssh().unwrap_or_default()
    }

    /// Sign `payload` as an SSHSIG structure bound to `namespace`.
    ///
    /// The signed preimage binds the namespace cryptographically, so a
    /// signature minted for one namespace never verifies under another.
    /// The result is armored as a `-----BEGIN SSH SIGNATURE-----` PEM
    /// block. Only the `ssh-sig` scheme exists here; there is no raw
    /// signing path to refuse.
    pub fn sign_sshsig(&self, namespace: &str, payload: &[u8]) -> Result<Vec<u8>, CustodyError> {
        // `ssh-key` builds the SSHSIG preimage (namespace-bound, SHA-256),
        // signs it Ed25519, and armors the result; its error Displays are
        // static strings, safe to forward without leaking key text.
        let signature = self
            .key
            .sign(namespace, HashAlg::Sha256, payload)
            .map_err(|e| CustodyError::Parse {
                detail: format!("sealed backend signing failed: {e}"),
            })?;
        let armored = signature
            .to_pem(LineEnding::LF)
            .map_err(|e| CustodyError::Parse {
                detail: format!("sealed backend armor failed: {e}"),
            })?;
        Ok(armored.into_bytes())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for BrokerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerKey")
            .field("provenance", &self.provenance)
            .field("algorithm", &self.key.algorithm())
            .field("key", &"<redacted>")
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Require bootstrap key material and move it into sealed custody.
///
/// Maps the absent field (including a new guest against an old host) to a
/// typed [`CustodyError::Absent`] clean refusal.
pub fn require_bootstrap_key(key: Option<BrokerSshKey>) -> Result<BrokerKey, CustodyError> {
    let Some(key) = key else {
        return Err(CustodyError::Absent {
            detail: "bootstrap carries no broker_key; old hosts omit the typed field".to_string(),
        });
    };
    BrokerKey::from_bootstrap(key)
}

/// Verify an armored SSHSIG signature against `payload`, binding both the
/// given `namespace` and the given authorized-keys-format `public_key`.
///
/// The namespace passed here is authoritative: it must equal the namespace
/// embedded in the armor (string check) and it recomputes the signed
/// preimage, so `sign(git)` verifies under `"git"` and fails under
/// `"file"`, and vice versa.
pub fn verify_sshsig(
    signature: &[u8],
    payload: &[u8],
    namespace: &str,
    public_key: &str,
) -> Result<(), SshSigVerifyError> {
    let signature = ssh_key::SshSig::from_pem(signature).map_err(|e| SshSigVerifyError::Parse {
        detail: e.to_string(),
    })?;
    let public_key: ssh_key::PublicKey =
        public_key
            .parse()
            .map_err(|e: ssh_key::Error| SshSigVerifyError::Parse {
                detail: e.to_string(),
            })?;
    public_key
        .verify(namespace, payload, &signature)
        .map_err(|e| match e {
            ssh_key::Error::PublicKey => SshSigVerifyError::KeyMismatch,
            ssh_key::Error::Namespace => SshSigVerifyError::NamespaceMismatch,
            _ => SshSigVerifyError::SignatureInvalid,
        })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test-only seed bytes (never real credentials).
    fn test_seed() -> Vec<u8> {
        vec![0x42; ED25519_SEED_BYTES]
    }

    /// A second fixed test-only seed for wrong-key checks.
    fn other_seed() -> Vec<u8> {
        vec![0x43; ED25519_SEED_BYTES]
    }

    fn test_key(seed: &[u8]) -> BrokerSshKey {
        BrokerSshKey {
            key_type: BROKER_KEY_TYPE_ED25519.to_string(),
            key_bytes: seed.to_vec(),
        }
    }

    #[test]
    fn custody_accepts_an_ed25519_seed() {
        let key = BrokerKey::from_bootstrap(test_key(&test_seed())).unwrap();
        assert_eq!(key.provenance(), "bootstrap.broker_key");
        assert!(key.public_key_openssh().starts_with("ssh-ed25519 "));
    }

    #[test]
    fn custody_absent_is_a_clean_refusal() {
        let err = require_bootstrap_key(None).unwrap_err();
        assert!(
            matches!(err, CustodyError::Absent { .. }),
            "absent field must be Absent, got: {err}"
        );
        assert!(err.to_string().contains("broker_key"));
    }

    #[test]
    fn custody_rejects_wrong_key_type() {
        let err = BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: "ssh-rsa".to_string(),
            key_bytes: test_seed(),
        })
        .unwrap_err();
        assert!(
            matches!(err, CustodyError::WrongType { .. }),
            "non-Ed25519 tag must be WrongType, got: {err}"
        );
        assert!(err.to_string().contains("ssh-rsa"));
    }

    #[test]
    fn custody_rejects_bad_seed_lengths() {
        for len in [0, 1, 31, 33, 64] {
            let err = BrokerKey::from_bootstrap(BrokerSshKey {
                key_type: BROKER_KEY_TYPE_ED25519.to_string(),
                key_bytes: vec![0x42; len],
            })
            .unwrap_err();
            assert!(
                matches!(err, CustodyError::Parse { .. }),
                "seed of {len} bytes must be Parse, got: {err}"
            );
        }
    }

    #[test]
    fn sign_emits_armored_sshsig_and_verifies() {
        let key = BrokerKey::from_bootstrap(test_key(&test_seed())).unwrap();
        let public = key.public_key_openssh();
        let payload = b"commit 0123456789abcdef";
        let signature = key.sign_sshsig("git", payload).unwrap();
        let text = std::str::from_utf8(&signature).unwrap();
        assert!(
            text.starts_with("-----BEGIN SSH SIGNATURE-----"),
            "custody must emit armored SSHSIG, got: {text}"
        );
        verify_sshsig(&signature, payload, "git", &public).unwrap();
    }

    #[test]
    fn namespace_binding_fails_both_directions() {
        let key = BrokerKey::from_bootstrap(test_key(&test_seed())).unwrap();
        let public = key.public_key_openssh();
        let payload = b"the same bytes";
        let git = key.sign_sshsig("git", payload).unwrap();
        let file = key.sign_sshsig("file", payload).unwrap();
        verify_sshsig(&git, payload, "git", &public).unwrap();
        verify_sshsig(&file, payload, "file", &public).unwrap();
        assert_eq!(
            verify_sshsig(&git, payload, "file", &public).unwrap_err(),
            SshSigVerifyError::NamespaceMismatch
        );
        assert_eq!(
            verify_sshsig(&file, payload, "git", &public).unwrap_err(),
            SshSigVerifyError::NamespaceMismatch
        );
    }

    #[test]
    fn verify_rejects_wrong_key_tampered_payload_and_garbage() {
        let key = BrokerKey::from_bootstrap(test_key(&test_seed())).unwrap();
        let other = BrokerKey::from_bootstrap(test_key(&other_seed())).unwrap();
        let public = key.public_key_openssh();
        let other_public = other.public_key_openssh();
        let payload = b"release artifact v1.2.3";
        let signature = key.sign_sshsig("git", payload).unwrap();

        assert_eq!(
            verify_sshsig(&signature, payload, "git", &other_public).unwrap_err(),
            SshSigVerifyError::KeyMismatch
        );
        let mut tampered = payload.to_vec();
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_sshsig(&signature, &tampered, "git", &public).unwrap_err(),
            SshSigVerifyError::SignatureInvalid
        );
        assert!(matches!(
            verify_sshsig(b"not-a-signature", payload, "git", &public).unwrap_err(),
            SshSigVerifyError::Parse { .. }
        ));
        assert!(matches!(
            verify_sshsig(&signature, payload, "git", "not-a-key").unwrap_err(),
            SshSigVerifyError::Parse { .. }
        ));
    }

    #[test]
    fn debug_impls_never_carry_key_bytes() {
        // Sound redaction check (no memory scans): the seed is 32
        // high-entropy bytes, so its hex rendering is distinctive — if any
        // Debug impl echoed key bytes, the rendering would contain it.
        let seed = test_seed();
        let key = BrokerKey::from_bootstrap(test_key(&seed)).unwrap();
        let rendered = format!("{key:?}");
        assert!(rendered.contains("bootstrap.broker_key"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex_of(&seed)));
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
