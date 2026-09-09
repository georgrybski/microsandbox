//! Prepare volatile runtime storage in the final guest root before user mounts.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use nix::mount::{self, MsFlags};

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MOUNTINFO_LIMIT: usize = 4 * 1024 * 1024;
const RUN_MODE: &str = "mode=755";
const RUN_FLAGS: MsFlags = MsFlags::MS_NODEV
    .union(MsFlags::MS_NOSUID)
    .union(MsFlags::MS_RELATIME);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn prepare_run() -> AgentdResult<()> {
    let mut metadata = Vec::new();
    File::open("/proc/self/mountinfo")
        .and_then(|file| {
            file.take((MOUNTINFO_LIMIT + 1) as u64)
                .read_to_end(&mut metadata)
        })
        .map_err(|error| AgentdError::Init(format!("read /proc/self/mountinfo: {error}")))?;
    prepare_run_at(Path::new("/run"), &metadata, mount_run_tmpfs)
}

fn prepare_run_at(
    run: &Path,
    mountinfo: &[u8],
    mount_tmpfs: impl FnOnce(&File) -> AgentdResult<()>,
) -> AgentdResult<()> {
    // Validate the complete mount listing before any directory or mount change.
    // A descendant mount must not be hidden by adding a new parent tmpfs.
    let preserve = contains_runtime_mount(mountinfo, run.as_os_str().as_bytes())?;
    match fs::symlink_metadata(run) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(AgentdError::Init(
                "/run must be a real directory, not a symlink or file".into(),
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound && !preserve => {
            fs::create_dir(run)
                .map_err(|error| AgentdError::Init(format!("create /run: {error}")))?;
        }
        Err(error) => return Err(AgentdError::Init(format!("inspect /run: {error}"))),
    }
    // Pin the no-follow directory. The mount syscall targets this descriptor,
    // not a later path lookup which could follow a replaced image symlink.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(run)
        .map_err(|error| {
            AgentdError::Init(format!("open /run without following symlinks: {error}"))
        })?;
    if preserve {
        return Ok(());
    }
    mount_tmpfs(&directory)
}

fn mount_run_tmpfs(directory: &File) -> AgentdResult<()> {
    let target = format!("/proc/self/fd/{}", directory.as_raw_fd());
    mount::mount(
        Some("tmpfs"),
        target.as_str(),
        Some("tmpfs"),
        RUN_FLAGS,
        Some(RUN_MODE),
    )
    .map_err(|error| AgentdError::Init(format!("mount volatile /run tmpfs: {error}")))
}

fn contains_runtime_mount(mountinfo: &[u8], run: &[u8]) -> AgentdResult<bool> {
    let invalid = || AgentdError::Init("invalid or incomplete /proc/self/mountinfo".into());
    if mountinfo.is_empty() || mountinfo.len() > MOUNTINFO_LIMIT || !mountinfo.ends_with(b"\n") {
        return Err(invalid());
    }
    let mut root_seen = false;
    let mut preserve = false;
    for line in mountinfo[..mountinfo.len() - 1].split(|byte| *byte == b'\n') {
        let fields: Vec<_> = line.split(|byte| *byte == b' ').collect();
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            return Err(invalid());
        };
        if separator < 6
            || fields.len() != separator + 4
            || fields.iter().any(|field| field.is_empty())
        {
            return Err(invalid());
        }
        for value in &fields[..2] {
            if !decimal(value) {
                return Err(invalid());
            }
        }
        let device: Vec<_> = fields[2].split(|byte| *byte == b':').collect();
        if device.len() != 2 || !device.iter().all(|value| decimal(value)) {
            return Err(invalid());
        }
        decode_mount_path(fields[3])?;
        let point = decode_mount_path(fields[4])?;
        root_seen |= point == b"/";
        preserve |= point == run || (point.starts_with(run) && point.get(run.len()) == Some(&b'/'));
    }
    if !root_seen {
        return Err(invalid());
    }
    Ok(preserve)
}

fn decimal(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(u8::is_ascii_digit)
}

fn decode_mount_path(encoded: &[u8]) -> AgentdResult<Vec<u8>> {
    let invalid = || AgentdError::Init("invalid escaped path in /proc/self/mountinfo".into());
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        let byte = encoded[index];
        if byte == b'\\' {
            let escape = encoded.get(index + 1..index + 4).ok_or_else(invalid)?;
            decoded.push(match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid()),
            });
            index += 4;
        } else {
            if matches!(byte, 0 | b' ' | b'\t' | b'\n') {
                return Err(invalid());
            }
            decoded.push(byte);
            index += 1;
        }
    }
    if !decoded.starts_with(b"/")
        || (decoded != b"/"
            && decoded[1..]
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b".."))
    {
        return Err(invalid());
    }
    Ok(decoded)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const ROOT_MOUNT: &[u8] = b"20 1 0:1 / / rw - overlay overlay rw\n";
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "msb-run-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn run(&self) -> PathBuf {
            self.0.join("run")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn listing(point: &str) -> Vec<u8> {
        [
            ROOT_MOUNT,
            format!("21 20 0:2 / {point} rw shared:1 future:2 - tmpfs tmpfs rw\n").as_bytes(),
        ]
        .concat()
    }

    #[test]
    fn exact_and_descendant_mounts_are_preserved_but_not_prefix_siblings() {
        for point in [
            "/run",
            "/run/cache",
            "/run/cache\\040name",
            "/run/cache\\134name",
        ] {
            assert!(
                contains_runtime_mount(&listing(point), b"/run").unwrap(),
                "{point}"
            );
        }
        for point in ["/", "/runaway", "/var/run", "/run\\040other"] {
            assert!(
                !contains_runtime_mount(&listing(point), b"/run").unwrap(),
                "{point}"
            );
        }
    }

    #[test]
    fn complete_listing_is_validated_even_after_a_matching_mount() {
        for invalid in [
            b"".as_slice(),
            b"garbage\n",
            b"20 1 0:1 / / rw - tmpfs tmpfs\n",
            b"20 x 0:1 / / rw - tmpfs tmpfs rw\n",
            b"20 1 0x1 / / rw - tmpfs tmpfs rw\n",
            b"20 1 0:1 / relative rw - tmpfs tmpfs rw\n",
            b"20 1 0:1 / /run\\999 rw - tmpfs tmpfs rw\n",
            b"20 1 0:1 / /run/../elsewhere rw - tmpfs tmpfs rw\n",
        ] {
            assert!(contains_runtime_mount(invalid, b"/run").is_err());
        }
        let mut trailing = listing("/run");
        trailing.extend_from_slice(b"malformed\n");
        assert!(contains_runtime_mount(&trailing, b"/run").is_err());
        assert!(contains_runtime_mount(&ROOT_MOUNT[..ROOT_MOUNT.len() - 1], b"/run").is_err());
        assert!(
            contains_runtime_mount(b"21 20 0:2 / /run rw - tmpfs tmpfs rw\n", b"/run").is_err()
        );
        assert!(contains_runtime_mount(&vec![b' '; MOUNTINFO_LIMIT + 1], b"/run").is_err());
    }

    #[test]
    fn kernel_path_escapes_and_non_utf8_bytes_are_not_lossily_decoded() {
        assert_eq!(
            decode_mount_path(b"/a\\040b\\011c\\012d\\134e").unwrap(),
            b"/a b\tc\nd\\e"
        );
        assert_eq!(decode_mount_path(b"/a\xff").unwrap(), b"/a\xff");
        assert_eq!(
            decode_mount_path(b"/a\rb\x0bc\x0c").unwrap(),
            b"/a\rb\x0bc\x0c"
        );
        for path in [
            b"/a\\".as_slice(),
            b"/a\\000",
            b"/a\0",
            b"/a//b",
            b"/a/.",
            b"/a/..",
        ] {
            assert!(decode_mount_path(path).is_err());
        }
    }

    #[test]
    fn invalid_mount_metadata_cannot_create_run_or_call_mount() {
        let fixture = Fixture::new();
        assert!(prepare_run_at(&fixture.run(), b"bad\n", |_| panic!("must not mount")).is_err());
        assert!(!fixture.run().exists());
    }

    #[test]
    fn symlinks_and_files_are_refused_without_following_or_modifying_them() {
        let fixture = Fixture::new();
        let target = fixture.0.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("canary"), b"unchanged").unwrap();
        for destination in [&target, &fixture.0.join("absent")] {
            symlink(destination, fixture.run()).unwrap();
            assert!(
                prepare_run_at(&fixture.run(), ROOT_MOUNT, |_| panic!("must not mount")).is_err()
            );
            fs::remove_file(fixture.run()).unwrap();
        }
        fs::write(fixture.run(), b"not a directory").unwrap();
        assert!(prepare_run_at(&fixture.run(), ROOT_MOUNT, |_| panic!("must not mount")).is_err());
        assert_eq!(fs::read(fixture.run()).unwrap(), b"not a directory");
        assert_eq!(fs::read(target.join("canary")).unwrap(), b"unchanged");
    }

    #[test]
    fn default_mount_pins_the_final_root_directory_without_deleting_old_contents() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.run()).unwrap();
        fs::write(
            fixture.run().join("old-image-data"),
            b"preserved underneath",
        )
        .unwrap();
        let called = Cell::new(false);
        prepare_run_at(&fixture.run(), ROOT_MOUNT, |directory| {
            called.set(true);
            assert_eq!(
                directory.metadata().unwrap().ino(),
                fs::metadata(fixture.run()).unwrap().ino()
            );
            assert_eq!(
                directory.metadata().unwrap().dev(),
                fs::metadata(fixture.run()).unwrap().dev()
            );
            Ok(())
        })
        .unwrap();
        assert!(called.get());
        assert_eq!(
            fs::read(fixture.run().join("old-image-data")).unwrap(),
            b"preserved underneath"
        );
        assert!(RUN_FLAGS.contains(MsFlags::MS_NODEV | MsFlags::MS_NOSUID));
        assert!(!RUN_FLAGS.intersects(
            MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY | MsFlags::MS_BIND | MsFlags::MS_REMOUNT
        ));
        assert_eq!(RUN_MODE, "mode=755");
    }

    #[test]
    fn existing_parent_and_child_mounts_do_not_trigger_any_overmount() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.run()).unwrap();
        fs::write(fixture.run().join("canary"), b"existing mount").unwrap();
        for point in [fixture.run(), fixture.run().join("child")] {
            prepare_run_at(&fixture.run(), &listing(point.to_str().unwrap()), |_| {
                panic!("must preserve mounts")
            })
            .unwrap();
        }
        assert_eq!(
            fs::read(fixture.run().join("canary")).unwrap(),
            b"existing mount"
        );
    }

    #[test]
    fn new_directory_and_mount_failure_have_explicit_results() {
        let fixture = Fixture::new();
        let error = prepare_run_at(&fixture.run(), ROOT_MOUNT, |_| {
            Err(AgentdError::Init("synthetic mount failure".into()))
        })
        .unwrap_err();
        assert!(error.to_string().contains("synthetic mount failure"));
        assert!(fixture.run().is_dir());
    }
}
