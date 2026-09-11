//! Explicit systemd-credential host identity for the managed broker service.
//!
//! Only the broker host key, its certificate and the CA public key enter the
//! guest. The CA private key and certificate issuance remain with the host
//! owner. This module performs no provisioning and opens no listener.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::ssh_key::{
    Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, certificate::CertType,
};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Static diagnostics never expose credential contents or parser input.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostIdentityError {
    /// Directory/files do not satisfy the explicit immutable input contract.
    #[error("broker host credential files are unavailable or unsafe")]
    Files,
    /// The explicit stable broker alias is not a valid DNS-style principal.
    #[error("broker host principal is invalid")]
    Principal,
    /// The complete key, certificate and CA identity did not validate.
    #[error("broker host certificate validation failed")]
    Certificate,
}

/// Load exactly `host-key`, `host-certificate`, and `host-ca.pub` from an
/// explicitly supplied absolute credentials directory. A raw-key-only or
/// implicit trust configuration is never accepted by this service path.
pub fn load_host_config(
    directory: &Path,
    principal: &str,
) -> Result<Arc<russh::server::Config>, HostIdentityError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostIdentityError::Certificate)?
        .as_secs();
    load_at(directory, principal, now)
}

fn load_at(
    directory: &Path,
    principal: &str,
    now: u64,
) -> Result<Arc<russh::server::Config>, HostIdentityError> {
    if !valid_principal(principal) {
        return Err(HostIdentityError::Principal);
    }
    let metadata = directory
        .symlink_metadata()
        .map_err(|_| HostIdentityError::Files)?;
    if !directory.is_absolute()
        || !metadata.is_dir()
        || metadata.mode() & 0o022 != 0
        || !owned(metadata.uid())
    {
        return Err(HostIdentityError::Files);
    }
    // The trusted systemd credentials directory is fixed for this process.
    // No hostile concurrent directory replacement guarantee is claimed.
    let key = read_credential(directory, "host-key", true)?;
    let certificate = read_credential(directory, "host-certificate", false)?;
    let ca = read_credential(directory, "host-ca.pub", false)?;
    validate(&key, &certificate, &ca, principal, now)
}

fn owned(uid: u32) -> bool {
    uid == 0 || uid == unsafe { libc::geteuid() }
}

fn read_credential(
    directory: &Path,
    name: &str,
    private: bool,
) -> Result<Zeroizing<Vec<u8>>, HostIdentityError> {
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join(name))
        .map_err(|_| HostIdentityError::Files)?;
    let metadata = file.metadata().map_err(|_| HostIdentityError::Files)?;
    let forbidden = if private { 0o077 } else { 0o022 };
    if !metadata.is_file()
        || !owned(metadata.uid())
        || metadata.mode() & forbidden != 0
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES as u64
    {
        return Err(HostIdentityError::Files);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| HostIdentityError::Files)?;
    if bytes.len() != metadata.len() as usize || bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(HostIdentityError::Files);
    }
    Ok(bytes)
}

fn valid_principal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn validate(
    key: &[u8],
    certificate: &[u8],
    ca: &[u8],
    principal: &str,
    now: u64,
) -> Result<Arc<russh::server::Config>, HostIdentityError> {
    let invalid = |_| HostIdentityError::Certificate;
    let key = PrivateKey::from_openssh(key).map_err(invalid)?;
    let certificate = Certificate::from_openssh(
        std::str::from_utf8(certificate).map_err(|_| HostIdentityError::Certificate)?,
    )
    .map_err(invalid)?;
    let ca = PublicKey::from_openssh(
        std::str::from_utf8(ca).map_err(|_| HostIdentityError::Certificate)?,
    )
    .map_err(invalid)?;
    if key.is_encrypted()
        || key.algorithm() != Algorithm::Ed25519
        || ca.key_data() == key.public_key().key_data()
        || certificate.public_key() != key.public_key().key_data()
        || certificate.cert_type() != CertType::Host
        || certificate.valid_principals() != [principal]
        || !certificate.critical_options().is_empty()
    {
        return Err(HostIdentityError::Certificate);
    }
    certificate
        .validate_at(now, [&ca.fingerprint(HashAlg::Sha256)])
        .map_err(invalid)?;
    // russh may also advertise the matching raw algorithm. Managed clients
    // require the certificate algorithm, scoped HostKeyAlias and this CA pin.
    Ok(Arc::new(russh::server::Config {
        keys: vec![key],
        certificates: vec![certificate],
        ..Default::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::BrokerKey;
    use microsandbox_protocol::bootstrap::BrokerSshKey;
    use russh::keys::ssh_key::{LineEnding, certificate::Builder};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn key(seed: u8) -> PrivateKey {
        BrokerKey::from_bootstrap(BrokerSshKey {
            key_type: "ed25519".into(),
            key_bytes: vec![seed; 32],
        })
        .unwrap()
        .private_key()
        .clone()
    }

    fn signed(kind: CertType, principals: &[&str], critical: bool) -> Certificate {
        let mut builder = Builder::new(
            vec![9; 32],
            key(1).public_key().key_data().clone(),
            100,
            200,
        )
        .unwrap();
        builder.cert_type(kind).unwrap();
        if principals.is_empty() {
            builder.all_principals_valid().unwrap();
        }
        for principal in principals {
            builder.valid_principal(*principal).unwrap();
        }
        if critical {
            builder.critical_option("unsupported", "value").unwrap();
        }
        builder.sign(&key(2)).unwrap()
    }

    fn check(
        certificate: Certificate,
        private: u8,
        ca: u8,
        now: u64,
    ) -> Result<Arc<russh::server::Config>, HostIdentityError> {
        validate(
            key(private).to_openssh(LineEnding::LF).unwrap().as_bytes(),
            certificate.to_openssh().unwrap().as_bytes(),
            key(ca).public_key().to_openssh().unwrap().as_bytes(),
            "broker.example",
            now,
        )
    }

    #[test]
    fn signed_host_certificate_and_matching_key_are_installed_together() {
        let config = check(
            signed(CertType::Host, &["broker.example"], false),
            1,
            2,
            150,
        )
        .unwrap();
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.certificates.len(), 1);
        assert_eq!(
            config.keys[0].public_key().key_data(),
            config.certificates[0].public_key()
        );
    }

    #[test]
    fn wrong_key_ca_time_type_principal_and_critical_options_fail_closed() {
        for (private, ca, now) in [(3, 2, 150), (1, 3, 150), (1, 2, 99), (1, 2, 200)] {
            assert!(
                check(
                    signed(CertType::Host, &["broker.example"], false),
                    private,
                    ca,
                    now
                )
                .is_err()
            );
        }
        for (kind, principals, critical) in [
            (CertType::User, vec!["broker.example"], false),
            (CertType::Host, vec!["other.example"], false),
            (CertType::Host, vec![], false),
            (
                CertType::Host,
                vec!["broker.example", "other.example"],
                false,
            ),
            (CertType::Host, vec!["broker.example"], true),
        ] {
            assert!(check(signed(kind, &principals, critical), 1, 2, 150).is_err());
        }
        let mut own_ca = Builder::new(
            vec![8; 32],
            key(1).public_key().key_data().clone(),
            100,
            200,
        )
        .unwrap();
        own_ca.cert_type(CertType::Host).unwrap();
        own_ca.valid_principal("broker.example").unwrap();
        assert!(
            check(own_ca.sign(&key(1)).unwrap(), 1, 1, 150).is_err(),
            "the broker credential must not also be the CA private key"
        );
    }

    fn files() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            (
                "host-key",
                key(1).to_openssh(LineEnding::LF).unwrap().to_string(),
            ),
            (
                "host-certificate",
                signed(CertType::Host, &["broker.example"], false)
                    .to_openssh()
                    .unwrap(),
            ),
            ("host-ca.pub", key(2).public_key().to_openssh().unwrap()),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        dir
    }

    #[test]
    fn explicit_credential_layout_accepts_only_the_complete_private_input() {
        let dir = files();
        assert!(load_at(dir.path(), "broker.example", 150).is_ok());
        std::fs::remove_file(dir.path().join("host-certificate")).unwrap();
        assert!(
            load_at(dir.path(), "broker.example", 150).is_err(),
            "no raw-key fallback"
        );
    }

    #[test]
    fn unsafe_file_type_permissions_size_and_principal_refuse() {
        let dir = files();
        for principal in [
            "",
            "*",
            "broker.example.",
            "Broker.example",
            "-broker",
            "broker..example",
            "../broker",
        ] {
            assert!(load_at(dir.path(), principal, 150).is_err());
        }
        let path = dir.path().join("host-key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_at(dir.path(), "broker.example", 150).is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(dir.path().join("host-ca.pub"), &path).unwrap();
        assert!(load_at(dir.path(), "broker.example", 150).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![0; MAX_CREDENTIAL_BYTES + 1]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_at(dir.path(), "broker.example", 150).is_err());
    }
}
