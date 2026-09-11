//! Read-only validation for an explicitly supplied build-time runtime.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Files that satisfy the prebuilt SDK build contract.
pub(crate) struct BuildRuntime {
    pub(crate) msb: PathBuf,
    pub(crate) firmware: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Only an absent override permits the caller's default installation path.
pub(crate) fn from_override(
    root: Option<OsString>,
    msb_name: &str,
    firmware_name: &str,
    expected_version: &str,
) -> io::Result<Option<BuildRuntime>> {
    root.map(|root| validate(Path::new(&root), msb_name, firmware_name, expected_version))
        .transpose()
}

/// Validate without creating directories, installing files, or downloading.
/// The caller must propagate errors instead of falling back to runtime state.
pub(crate) fn validate(
    root: &Path,
    msb_name: &str,
    firmware_name: &str,
    expected_version: &str,
) -> io::Result<BuildRuntime> {
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a non-empty absolute directory containing bin/msb and lib/ firmware",
        ));
    }
    let runtime = BuildRuntime {
        msb: root.join("bin").join(msb_name),
        firmware: root.join("lib").join(firmware_name),
    };
    for path in [&runtime.msb, &runtime.firmware] {
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("required runtime file is missing: {}", path.display()),
            ));
        }
    }
    let output = Command::new(&runtime.msb)
        .arg("--version")
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot execute {} --version: {error}",
                    runtime.msb.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} --version failed: {}",
                runtime.msb.display(),
                output.status
            ),
        ));
    }
    let expected = format!("msb {expected_version}");
    if String::from_utf8_lossy(&output.stdout).trim() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} --version must report {expected:?}",
                runtime.msb.display()
            ),
        ));
    }
    Ok(runtime)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    const VERSION: &str = "0.6.16";
    const FIRMWARE: &str = "libkrunfw.so.5.6.1";
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        root: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new(version: &str) -> Self {
            // A concurrent fork can retain a fixture's writable descriptor
            // until exec, causing ETXTBSY when another test executes that file.
            let guard = FIXTURE_LOCK
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let root = std::env::temp_dir().join(format!(
                "msb-build-runtime-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::create_dir(root.join("bin")).unwrap();
            fs::create_dir(root.join("lib")).unwrap();
            fs::write(
                root.join("bin/msb"),
                format!("#!/bin/sh\nprintf 'msb {version}\\n'\n"),
            )
            .unwrap();
            fs::set_permissions(root.join("bin/msb"), fs::Permissions::from_mode(0o555)).unwrap();
            fs::write(root.join("lib").join(FIRMWARE), "fixture firmware").unwrap();
            Self {
                root,
                _guard: guard,
            }
        }

        fn validate(&self) -> io::Result<BuildRuntime> {
            validate(&self.root, "msb", FIRMWARE, VERSION)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for path in [&self.root, &self.root.join("bin"), &self.root.join("lib")] {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn accepts_matching_runtime_in_read_only_directories() {
        let fixture = Fixture::new(VERSION);
        for path in [
            &fixture.root,
            &fixture.root.join("bin"),
            &fixture.root.join("lib"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }
        let runtime = fixture.validate().unwrap();
        assert_eq!(runtime.msb, fixture.root.join("bin/msb"));
        assert_eq!(runtime.firmware, fixture.root.join("lib").join(FIRMWARE));
        assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 2);
    }

    #[test]
    fn missing_directory_is_not_created() {
        let fixture = Fixture::new(VERSION);
        let missing = fixture.root.join("missing");
        assert!(validate(&missing, "msb", FIRMWARE, VERSION).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn rejects_missing_binary_without_installing_it() {
        let fixture = Fixture::new(VERSION);
        fs::remove_file(fixture.root.join("bin/msb")).unwrap();
        assert!(fixture.validate().is_err());
        assert!(!fixture.root.join("bin/msb").exists());
    }

    #[test]
    fn rejects_missing_firmware_without_installing_it() {
        let fixture = Fixture::new(VERSION);
        let firmware = fixture.root.join("lib").join(FIRMWARE);
        fs::remove_file(&firmware).unwrap();
        assert!(fixture.validate().is_err());
        assert!(!firmware.exists());
    }

    #[test]
    fn rejects_wrong_version() {
        let fixture = Fixture::new("0.0.0");
        let error = fixture.validate().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(VERSION));
    }

    #[test]
    fn rejects_non_executable_binary() {
        let fixture = Fixture::new(VERSION);
        fs::set_permissions(
            fixture.root.join("bin/msb"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn rejects_empty_and_relative_overrides() {
        for path in ["", "relative-runtime"] {
            let error = validate(Path::new(path), "msb", FIRMWARE, VERSION)
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn only_absent_override_selects_default_installation() {
        assert!(
            from_override(None, "msb", FIRMWARE, VERSION)
                .unwrap()
                .is_none()
        );
        for root in ["", "relative-runtime"] {
            assert!(from_override(Some(root.into()), "msb", FIRMWARE, VERSION).is_err());
        }
        let fixture = Fixture::new("0.0.0");
        assert!(
            from_override(Some(fixture.root.clone().into()), "msb", FIRMWARE, VERSION).is_err()
        );
    }
}
