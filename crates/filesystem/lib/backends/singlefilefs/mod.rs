//! Isolated host-file filesystem backend.
//!
//! `SingleFileFs` presents a synthetic directory containing exactly one host
//! file. The selected file uses the platform passthrough implementation for
//! data and metadata operations, while this facade prevents the guest from
//! discovering or mutating any sibling names in the host directory.

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    io,
    path::PathBuf,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use super::passthroughfs::{PassthroughConfig, PassthroughFs};
use crate::{
    Context, DirEntry, DynFileSystem, Entry, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ROOT_INODE: u64 = 1;
const ROOT_HANDLE: u64 = 0;

const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFMT: u32 = 0o170000;

const LINUX_ENOENT: i32 = 2;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A virtio-fs backend exposing one host file beneath a synthetic root.
pub struct SingleFileFs {
    inner: PassthroughFs,
    inner_name: CString,
    guest_name: &'static [u8],
    current_inode: AtomicU64,
    lookup_refs: RwLock<HashMap<u64, u64>>,
    open_handles: RwLock<HashMap<u64, OpenHandleAdmission>>,
}

#[derive(Clone, Copy)]
struct OpenHandleAdmission {
    guest_inode: u64,
    inner_inode: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SingleFileFs {
    /// Create an isolated view of `source` under `guest_name`.
    ///
    /// The source is canonicalized once so the passthrough backend is anchored
    /// to a real parent directory. The guest-facing namespace is synthetic and
    /// never exposes that parent or any of its other entries.
    pub fn new(
        source: PathBuf,
        guest_name: String,
        mut cfg: PassthroughConfig,
    ) -> io::Result<Self> {
        let source = std::fs::canonicalize(source)?;
        let metadata = std::fs::metadata(&source)?;
        if !metadata.is_file() {
            return Err(linux_error(LINUX_EISDIR));
        }

        let parent = source
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no parent"))?;
        let inner_name = source
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no name"))?
            .to_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "host filename is not valid UTF-8",
                )
            })?
            .to_string();

        if guest_name.is_empty()
            || guest_name == "."
            || guest_name == ".."
            || guest_name.contains('/')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "single-file guest name must be a normal path component",
            ));
        }

        cfg.root_dir = parent.to_path_buf();
        // The passthrough backend needs the parent as its namespace anchor,
        // but quota accounting must include only the selected file.
        cfg.quota_root = Some(source.clone());
        cfg.no_symlink_root = true;
        cfg.inject_init = false;
        // The host may atomically replace the selected path. Positive dentry
        // caching would otherwise keep directing new opens to the unlinked
        // inode, which a pathname-based passthrough backend cannot reopen.
        cfg.entry_timeout = Duration::ZERO;
        // Host writes bypass FUSE, so expire attributes immediately. With
        // AUTO_INVAL_DATA negotiated below, each guest read revalidates mtime
        // and invalidates cached contents when the host changed them.
        cfg.attr_timeout = Duration::ZERO;

        let inner_name = CString::new(inner_name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "host filename contains NUL")
        })?;
        let inner = PassthroughFs::new_with_stat_probe(cfg, Some(&inner_name))?;
        let guest_name = CString::new(guest_name)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "guest filename contains NUL")
            })?
            .into_bytes()
            .into_boxed_slice();

        Ok(Self {
            inner,
            inner_name,
            // The backend lives for the VM lifetime. A stable name lets both
            // vector and streaming readdir callbacks borrow it safely.
            guest_name: Box::leak(guest_name),
            current_inode: AtomicU64::new(0),
            lookup_refs: RwLock::new(HashMap::new()),
            open_handles: RwLock::new(HashMap::new()),
        })
    }

    /// Resolve the selected name and update its admission state.
    ///
    /// The current inode owns one inner lookup reference even when the kernel
    /// owns none. This pin makes the inode emitted by plain `readdir` usable,
    /// while `lookup_refs` tracks only references that FUSE may later forget.
    fn admit_file(&self, ctx: Context, kernel_lookup: bool) -> io::Result<Entry> {
        let entry = self.inner.lookup(ctx, ROOT_INODE, &self.inner_name)?;
        if u32::from(entry.attr.st_mode) & S_IFMT != S_IFREG {
            self.inner.forget(ctx, entry.inode, 1);
            return Err(linux_error(LINUX_ENOENT));
        }

        let (release_old_pin, release_redundant_lookup) = {
            let mut refs = self.lookup_refs.write().unwrap();
            let old_inode = self.current_inode.load(Ordering::Acquire);
            let was_current = old_inode == entry.inode;
            let previous_refs = refs.get(&entry.inode).copied().unwrap_or(0);
            let previous_inner_refs = previous_refs + u64::from(was_current && previous_refs == 0);
            let next_refs = previous_refs + u64::from(kernel_lookup);
            let next_inner_refs = next_refs.max(1);

            let release_old_pin = if old_inode != 0 && !was_current {
                if refs.get(&old_inode).copied().unwrap_or(0) == 0 {
                    refs.remove(&old_inode);
                    Some(old_inode)
                } else {
                    None
                }
            } else {
                None
            };

            refs.insert(entry.inode, next_refs);
            self.current_inode.store(entry.inode, Ordering::Release);

            // `inner.lookup` added one reference. When an existing reference
            // can become the current pin, release the newly added surplus.
            let release_redundant_lookup = previous_inner_refs + 1 > next_inner_refs;
            (release_old_pin, release_redundant_lookup)
        };

        if let Some(old_inode) = release_old_pin {
            self.inner.forget(ctx, old_inode, 1);
        }
        if release_redundant_lookup {
            self.inner.forget(ctx, entry.inode, 1);
        }
        Ok(entry)
    }

    fn lookup_file(&self, ctx: Context) -> io::Result<Entry> {
        self.admit_file(ctx, true)
    }

    fn refresh_file(&self, ctx: Context) -> io::Result<Entry> {
        self.admit_file(ctx, false)
    }

    fn require_lookup(&self, inode: u64) -> io::Result<()> {
        if inode != 0
            && (self.current_inode.load(Ordering::Acquire) == inode
                || self
                    .lookup_refs
                    .read()
                    .unwrap()
                    .get(&inode)
                    .copied()
                    .unwrap_or(0)
                    != 0)
        {
            Ok(())
        } else {
            Err(linux_error(LINUX_ENOENT))
        }
    }

    fn inner_inode_for_handle(&self, inode: u64, handle: u64) -> io::Result<u64> {
        self.open_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|admission| admission.guest_inode == inode)
            .map(|admission| admission.inner_inode)
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }

    fn root_entries(&self) -> Vec<DirEntry<'static>> {
        let file_inode = self.current_inode.load(Ordering::Acquire);
        vec![
            DirEntry {
                ino: ROOT_INODE,
                offset: 1,
                type_: DT_DIR,
                name: b".",
            },
            DirEntry {
                ino: ROOT_INODE,
                offset: 2,
                type_: DT_DIR,
                name: b"..",
            },
            DirEntry {
                ino: file_inode,
                offset: 3,
                type_: DT_REG,
                name: self.guest_name,
            },
        ]
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for SingleFileFs {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let options = self.inner.init(capable)?;
        let options = if capable.contains(FsOptions::AUTO_INVAL_DATA) {
            // Single-file binds are externally mutable. Ask the guest kernel
            // to compare refreshed attributes before serving cached pages.
            options | FsOptions::AUTO_INVAL_DATA
        } else {
            options
        };
        Ok(options)
    }

    fn destroy(&self) {
        self.open_handles.write().unwrap().clear();
        self.lookup_refs.write().unwrap().clear();
        self.inner.destroy();
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        if parent != ROOT_INODE {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        if name.to_bytes() != self.guest_name {
            return Err(linux_error(LINUX_ENOENT));
        }
        self.lookup_file(ctx)
    }

    fn forget(&self, ctx: Context, inode: u64, count: u64) {
        let forgotten = {
            let mut refs = self.lookup_refs.write().unwrap();
            let Some(current) = refs.get_mut(&inode) else {
                return;
            };
            let forgotten = count.min(*current);
            *current -= forgotten;
            let exhausted = *current == 0;
            let is_current = self.current_inode.load(Ordering::Acquire) == inode;
            if exhausted && !is_current {
                refs.remove(&inode);
            }
            // The final current-inode reference becomes the façade's pin
            // instead of being released to the inner backend.
            if is_current && exhausted {
                forgotten.saturating_sub(1)
            } else {
                forgotten
            }
        };
        if forgotten != 0 {
            self.inner.forget(ctx, inode, forgotten);
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        if inode == ROOT_INODE {
            return Ok((root_stat(), Duration::from_secs(5)));
        }
        let inner_inode = match handle {
            Some(handle) => self.inner_inode_for_handle(inode, handle)?,
            None => {
                self.require_lookup(inode)?;
                self.refresh_file(ctx)?.inode
            }
        };
        self.inner.getattr(ctx, inner_inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        let inner_inode = match handle {
            Some(handle) => self.inner_inode_for_handle(inode, handle)?,
            None => {
                self.require_lookup(inode)?;
                self.refresh_file(ctx)?.inode
            }
        };
        self.inner.setattr(ctx, inner_inode, attr, handle, valid)
    }

    fn open(
        &self,
        ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            return Err(linux_error(LINUX_EISDIR));
        }
        self.require_lookup(inode)?;
        // The FUSE client may reuse a cached node ID without another LOOKUP.
        // Resolve the selected host path at OPEN so a new descriptor follows
        // an atomic replacement, independently of already-open descriptors.
        let inner_inode = self.refresh_file(ctx)?.inode;
        let opened = self.inner.open(ctx, inner_inode, kill_priv, flags)?;
        if let Some(handle) = opened.0 {
            self.open_handles.write().unwrap().insert(
                handle,
                OpenHandleAdmission {
                    guest_inode: inode,
                    inner_inode,
                },
            );
        }
        Ok(opened)
    }

    fn read(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        writer: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner.read(
            ctx,
            inner_inode,
            handle,
            writer,
            size,
            offset,
            lock_owner,
            flags,
        )
    }

    fn write(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        reader: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner.write(
            ctx,
            inner_inode,
            handle,
            reader,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner.flush(ctx, inner_inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner.fsync(ctx, inner_inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner
            .fallocate(ctx, inner_inode, handle, mode, offset, length)
    }

    fn release(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner.release(
            ctx,
            inner_inode,
            flags,
            handle,
            flush,
            flock_release,
            lock_owner,
        )?;
        self.open_handles.write().unwrap().remove(&handle);
        Ok(())
    }

    fn statfs(&self, ctx: Context, _inode: u64) -> io::Result<statvfs64> {
        self.inner.statfs(ctx, ROOT_INODE)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.require_lookup(inode)?;
        let inner_inode = self.refresh_file(ctx)?.inode;
        self.inner.setxattr(ctx, inner_inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.require_lookup(inode)?;
        let inner_inode = self.refresh_file(ctx)?.inode;
        self.inner.getxattr(ctx, inner_inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        self.require_lookup(inode)?;
        let inner_inode = self.refresh_file(ctx)?.inode;
        self.inner.listxattr(ctx, inner_inode, size)
    }

    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> io::Result<()> {
        self.require_lookup(inode)?;
        let inner_inode = self.refresh_file(ctx)?.inode;
        self.inner.removexattr(ctx, inner_inode, name)
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            Ok((Some(ROOT_HANDLE), OpenOptions::empty()))
        } else {
            Err(linux_error(LINUX_ENOTDIR))
        }
    }

    fn readdir(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        if inode != ROOT_INODE || handle != ROOT_HANDLE {
            return Err(linux_error(LINUX_EBADF));
        }
        // Plain readdir does not create a kernel lookup reference, so refresh
        // only the façade-owned current-inode pin.
        // Masked single file → empty synthetic mount (policy decision), so guests see
        // dot entries rather than EIO.
        let masked = match self.refresh_file(ctx) {
            Ok(_) => false,
            Err(e)
                if e.raw_os_error() == Some(LINUX_ENOENT)
                    || e.kind() == io::ErrorKind::NotFound =>
            {
                true
            }
            Err(e) => return Err(e),
        };
        if masked {
            return Ok(self
                .root_entries()
                .into_iter()
                .take(2)
                .skip(offset as usize)
                .collect());
        }
        Ok(self
            .root_entries()
            .into_iter()
            .skip(offset as usize)
            .collect())
    }

    fn readdirplus(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        if inode != ROOT_INODE || handle != ROOT_HANDLE {
            return Err(linux_error(LINUX_EBADF));
        }
        // Masked single file → empty synthetic mount (policy decision), so guests see
        // dot entries rather than EIO.
        let file_entry = match self.lookup_file(ctx) {
            Ok(entry) => entry,
            Err(e)
                if e.raw_os_error() == Some(LINUX_ENOENT)
                    || e.kind() == io::ErrorKind::NotFound =>
            {
                let mut dir_entries = self.root_entries().into_iter();
                let entries = vec![
                    (dir_entries.next().unwrap(), root_entry()),
                    (dir_entries.next().unwrap(), root_entry()),
                ];
                return Ok(entries.into_iter().skip(offset as usize).collect());
            }
            Err(e) => return Err(e),
        };
        let mut dir_entries = self.root_entries().into_iter();
        let entries = vec![
            (dir_entries.next().unwrap(), root_entry()),
            (dir_entries.next().unwrap(), root_entry()),
            (dir_entries.next().unwrap(), file_entry),
        ];
        Ok(entries.into_iter().skip(offset as usize).collect())
    }

    fn fsyncdir(&self, _ctx: Context, inode: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        if inode == ROOT_INODE && handle == ROOT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        if inode == ROOT_INODE && handle == ROOT_HANDLE {
            Ok(())
        } else {
            Err(linux_error(LINUX_EBADF))
        }
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        if inode == ROOT_INODE {
            return if mask & 0o2 == 0 {
                Ok(())
            } else {
                Err(linux_error(LINUX_EACCES))
            };
        }
        self.require_lookup(inode)?;
        let inner_inode = self.refresh_file(ctx)?.inode;
        self.inner.access(ctx, inner_inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let inner_inode = self.inner_inode_for_handle(inode, handle)?;
        self.inner.lseek(ctx, inner_inode, handle, offset, whence)
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: u64,
        handle_in: u64,
        offset_in: u64,
        inode_out: u64,
        handle_out: u64,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        let inner_inode_in = self.inner_inode_for_handle(inode_in, handle_in)?;
        let inner_inode_out = self.inner_inode_for_handle(inode_out, handle_out)?;
        self.inner.copyfilerange(
            ctx,
            inner_inode_in,
            handle_in,
            offset_in,
            inner_inode_out,
            handle_out,
            offset_out,
            len,
            flags,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn root_entry() -> Entry {
    Entry {
        inode: ROOT_INODE,
        generation: 0,
        attr: root_stat(),
        attr_flags: 0,
        attr_timeout: Duration::from_secs(5),
        entry_timeout: Duration::from_secs(5),
    }
}

fn root_stat() -> stat64 {
    let mut stat: stat64 = unsafe { std::mem::zeroed() };
    stat.st_ino = ROOT_INODE;
    stat.st_mode = (S_IFDIR | 0o555) as _;
    stat.st_nlink = 2;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_blksize = 4096;
    stat
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    const LINUX_EROFS: i32 = 30;
    const LINUX_O_WRONLY: u32 = 1;

    struct CaptureWriter {
        bytes: Vec<u8>,
    }

    impl ZeroCopyWriter for CaptureWriter {
        fn write_from(
            &mut self,
            file: &std::fs::File,
            count: usize,
            offset: u64,
        ) -> io::Result<usize> {
            let mut file = file.try_clone()?;
            file.seek(SeekFrom::Start(offset))?;
            file.take(count as u64).read_to_end(&mut self.bytes)
        }
    }

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    #[test]
    fn exposes_only_the_selected_readonly_file_without_hardlinking() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("selected.txt");
        std::fs::write(&source, b"initial").unwrap();
        std::fs::write(temp.path().join("sibling.txt"), b"secret").unwrap();

        #[cfg(unix)]
        let links_before = std::fs::metadata(&source).unwrap().nlink();
        let fs = SingleFileFs::new(
            source.clone(),
            "config.txt".to_string(),
            PassthroughConfig {
                readonly: true,
                ..Default::default()
            },
        )
        .unwrap();

        // A source mutation after construction remains visible, proving the
        // backend did not stage a copy. Read-only permissions also exercise
        // the same access pattern as foreign-owned system files.
        std::fs::write(&source, b"updated").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o444)).unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let entry = fs.lookup(context(), ROOT_INODE, c"config.txt").unwrap();
        #[cfg(unix)]
        assert_eq!(std::fs::metadata(&source).unwrap().nlink(), links_before);
        let sibling_error = match fs.lookup(context(), ROOT_INODE, c"sibling.txt") {
            Ok(_) => panic!("a sibling name must not be guest-visible"),
            Err(error) => error,
        };
        assert_eq!(sibling_error.raw_os_error(), Some(LINUX_ENOENT));

        let (handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        fs.read(context(), entry.inode, handle, &mut writer, 64, 0, None, 0)
            .unwrap();
        fs.release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
        assert_eq!(writer.bytes, b"updated");

        let write_error = fs
            .open(context(), entry.inode, false, LINUX_O_WRONLY)
            .unwrap_err();
        assert_eq!(write_error.raw_os_error(), Some(LINUX_EROFS));

        let (directory_handle, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let entries = fs
            .readdir(context(), ROOT_INODE, directory_handle.unwrap(), 4096, 0)
            .unwrap();
        let names = entries.iter().map(|entry| entry.name).collect::<Vec<_>>();
        assert_eq!(names, vec![b".".as_slice(), b"..", b"config.txt"]);
    }

    #[test]
    fn rejects_directories_and_non_component_guest_names() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            SingleFileFs::new(
                temp.path().to_path_buf(),
                "config.txt".to_string(),
                PassthroughConfig::default(),
            )
            .is_err()
        );

        let source = temp.path().join("selected.txt");
        std::fs::write(&source, b"data").unwrap();
        for name in ["", ".", "..", "nested/config.txt"] {
            assert!(
                SingleFileFs::new(
                    source.clone(),
                    name.to_string(),
                    PassthroughConfig::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn negotiates_automatic_data_invalidation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("selected.txt");
        std::fs::write(&source, b"initial").unwrap();

        let fs = SingleFileFs::new(
            source,
            "config.txt".to_string(),
            PassthroughConfig {
                attr_timeout: Duration::from_secs(60),
                ..Default::default()
            },
        )
        .unwrap();
        let options = fs.init(FsOptions::AUTO_INVAL_DATA).unwrap();

        assert!(options.contains(FsOptions::AUTO_INVAL_DATA));
        #[cfg(unix)]
        {
            assert_eq!(fs.inner.cfg.entry_timeout, Duration::ZERO);
            assert_eq!(fs.inner.cfg.attr_timeout, Duration::ZERO);
        }
    }

    #[test]
    fn replacement_keeps_the_old_open_handle_valid() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("selected.txt");
        let replacement = temp.path().join("replacement.txt");
        std::fs::write(&source, b"old contents").unwrap();
        std::fs::write(&replacement, b"new contents").unwrap();

        let fs = SingleFileFs::new(
            source.clone(),
            "config.txt".to_string(),
            PassthroughConfig::default(),
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let old_entry = fs.lookup(context(), ROOT_INODE, c"config.txt").unwrap();
        #[cfg(unix)]
        let old_flags = libc::O_RDWR as u32;
        #[cfg(windows)]
        let old_flags = 0;
        let (old_handle, _) = fs
            .open(context(), old_entry.inode, false, old_flags)
            .unwrap();
        let old_handle = old_handle.unwrap();

        #[cfg(windows)]
        std::fs::remove_file(&source).unwrap();
        std::fs::rename(&replacement, &source).unwrap();

        // Linux may issue OPEN against the cached old node ID without another
        // LOOKUP. A new descriptor must still follow the selected pathname.
        let (replacement_attr, _) = fs.getattr(context(), old_entry.inode, None).unwrap();
        assert_eq!(replacement_attr.st_size, b"new contents".len() as i64);
        let (cached_handle, _) = fs.open(context(), old_entry.inode, false, 0).unwrap();
        let cached_handle = cached_handle.unwrap();
        let mut cached_writer = CaptureWriter { bytes: Vec::new() };
        fs.read(
            context(),
            old_entry.inode,
            cached_handle,
            &mut cached_writer,
            64,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(cached_writer.bytes, b"new contents");
        fs.release(
            context(),
            old_entry.inode,
            0,
            cached_handle,
            false,
            false,
            None,
        )
        .unwrap();

        let directory_entries = fs
            .readdir(context(), ROOT_INODE, ROOT_HANDLE, 4096, 0)
            .unwrap();
        let replacement_inode = directory_entries.last().unwrap().ino;
        // Unix passthrough identities follow host inodes, while Windows keeps
        // a stable synthetic node ID for the selected pathname.
        #[cfg(unix)]
        assert_ne!(old_entry.inode, replacement_inode);
        fs.getattr(context(), replacement_inode, None).unwrap();

        let new_entry = fs.lookup(context(), ROOT_INODE, c"config.txt").unwrap();
        #[cfg(unix)]
        assert_ne!(old_entry.inode, new_entry.inode);

        // FUSE may drop the pathname lookup before the descriptor is closed.
        // The handle admission must independently retain access to that inode.
        fs.forget(context(), old_entry.inode, 1);
        #[cfg(unix)]
        {
            // Handle-based setattr must keep targeting this descriptor after
            // its inode has been detached from the host namespace.
            let mut detached_attr: stat64 = unsafe { std::mem::zeroed() };
            detached_attr.st_size = 3;
            fs.setattr(
                context(),
                old_entry.inode,
                detached_attr,
                Some(old_handle),
                SetattrValid::SIZE,
            )
            .unwrap();
        }
        let mut old_writer = CaptureWriter { bytes: Vec::new() };
        fs.read(
            context(),
            old_entry.inode,
            old_handle,
            &mut old_writer,
            64,
            0,
            None,
            0,
        )
        .unwrap();
        #[cfg(unix)]
        assert_eq!(old_writer.bytes, b"old");
        #[cfg(windows)]
        assert_eq!(old_writer.bytes, b"old contents");
        fs.release(
            context(),
            old_entry.inode,
            0,
            old_handle,
            false,
            false,
            None,
        )
        .unwrap();

        let (new_handle, _) = fs.open(context(), new_entry.inode, false, 0).unwrap();
        let new_handle = new_handle.unwrap();
        let mut new_writer = CaptureWriter { bytes: Vec::new() };
        fs.read(
            context(),
            new_entry.inode,
            new_handle,
            &mut new_writer,
            64,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(new_writer.bytes, b"new contents");
        fs.release(
            context(),
            new_entry.inode,
            0,
            new_handle,
            false,
            false,
            None,
        )
        .unwrap();
        fs.forget(context(), new_entry.inode, 1);
    }

    //----------------------------------------------------------------------------------------------
    // Policy helpers (unix-only) — copied from passthroughfs/unix/tests/test_mount_policy.rs
    //----------------------------------------------------------------------------------------------

    #[cfg(unix)]
    const LINUX_O_RDONLY: u32 = 0;
    #[cfg(unix)]
    const LINUX_O_RDWR: u32 = 2;
    #[cfg(unix)]
    const LINUX_ENOSPC: i32 = 28;

    #[cfg(unix)]
    fn policy_program(
        mask: &[&str],
        unmask: &[&str],
    ) -> crate::backends::passthroughfs::mount_policy::MountPolicyProgram {
        use crate::backends::passthroughfs::mount_policy::{
            CaseSensitivity, CompiledRuleSet, MountPolicyProgram, PathPolicyRule, Pattern,
            RuleEffect, RuleOrigin, ScopeKind,
        };
        use std::path::PathBuf;
        let origin = RuleOrigin {
            layer: "test".to_string(),
            file: PathBuf::from("test.json"),
            scope_kind: ScopeKind::Workload,
        };
        let rules = mask
            .iter()
            .map(|pattern| PathPolicyRule {
                effect: RuleEffect::Mask,
                pattern: Pattern::parse(pattern).unwrap(),
                overridable: true,
                origin: origin.clone(),
            })
            .chain(unmask.iter().map(|pattern| PathPolicyRule {
                effect: RuleEffect::Unmask,
                pattern: Pattern::parse(pattern).unwrap(),
                overridable: true,
                origin: origin.clone(),
            }))
            .collect();
        MountPolicyProgram {
            version: 1,
            rules,
            protect: Vec::new(),
            writes: CompiledRuleSet::default(),
            case_sensitivity: CaseSensitivity::Sensitive,
        }
    }

    #[cfg(unix)]
    fn write_rule(
        pattern: &str,
        scope_kind: crate::backends::passthroughfs::mount_policy::ScopeKind,
        overridable: bool,
    ) -> crate::backends::passthroughfs::mount_policy::PathPolicyRule {
        use crate::backends::passthroughfs::mount_policy::{
            PathPolicyRule, Pattern, RuleEffect, RuleOrigin,
        };
        use std::path::PathBuf;
        PathPolicyRule {
            effect: RuleEffect::Mask,
            pattern: Pattern::parse(pattern).unwrap(),
            overridable,
            origin: RuleOrigin {
                layer: "test".to_string(),
                file: PathBuf::from("test.json"),
                scope_kind,
            },
        }
    }

    #[cfg(unix)]
    fn write_program(
        protect: &[&str],
        allow: &[(
            &str,
            crate::backends::passthroughfs::mount_policy::ScopeKind,
            bool,
        )],
        deny: &[(
            &str,
            crate::backends::passthroughfs::mount_policy::ScopeKind,
            bool,
        )],
    ) -> crate::backends::passthroughfs::mount_policy::MountPolicyProgram {
        use crate::backends::passthroughfs::mount_policy::{
            CaseSensitivity, CompiledRuleSet, MountPolicyProgram,
        };
        MountPolicyProgram {
            version: 1,
            rules: Vec::new(),
            protect: protect
                .iter()
                .map(|pattern| {
                    write_rule(
                        pattern,
                        crate::backends::passthroughfs::mount_policy::ScopeKind::Workload,
                        true,
                    )
                })
                .collect(),
            writes: CompiledRuleSet {
                allow: allow
                    .iter()
                    .map(|(pattern, scope_kind, overridable)| {
                        write_rule(pattern, *scope_kind, *overridable)
                    })
                    .collect(),
                deny: deny
                    .iter()
                    .map(|(pattern, scope_kind, overridable)| {
                        write_rule(pattern, *scope_kind, *overridable)
                    })
                    .collect(),
            },
            case_sensitivity: CaseSensitivity::Sensitive,
        }
    }

    #[cfg(unix)]
    struct SliceReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    #[cfg(unix)]
    impl<'a> SliceReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0 }
        }
    }

    #[cfg(unix)]
    impl<'a> crate::ZeroCopyReader for SliceReader<'a> {
        fn read_to(
            &mut self,
            file: &std::fs::File,
            count: usize,
            offset: u64,
        ) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            let remaining = &self.data[self.pos..];
            let to_write = std::cmp::min(count, remaining.len());
            if to_write == 0 {
                return Ok(0);
            }
            let n = unsafe {
                libc::pwrite(
                    file.as_raw_fd(),
                    remaining.as_ptr() as *const libc::c_void,
                    to_write,
                    offset as i64,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            self.pos += n;
            Ok(n)
        }
    }

    //----------------------------------------------------------------------------------------------
    // T1 [P0] no-policy regression — absent mask_policy is byte-identical to default
    //----------------------------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn t1_no_policy_regression_lookup_read_readdir_byte_identical_to_default() {
        // Mirrors PassthroughFs test `absent_mask_policy_is_byte_identical_to_default` (test_mount_policy.rs:78).
        // Both an explicit `mask_policy = None` and the default `PassthroughConfig::default()` must
        // expose the file identically: lookup succeeds, read returns bytes, readdir has 3 entries.
        let make_fs = |explicit_none: bool| {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("visible.txt");
            std::fs::write(&source, b"hello world").unwrap();
            let cfg = if explicit_none {
                let mut c = PassthroughConfig::default();
                c.mask_policy = None;
                c
            } else {
                PassthroughConfig::default()
            };
            let fs = SingleFileFs::new(source.clone(), "visible.txt".to_string(), cfg).unwrap();
            fs.init(FsOptions::empty()).unwrap();
            (temp, fs)
        };

        let (_tmp_explicit, fs_explicit) = make_fs(true);
        let (_tmp_default, fs_default) = make_fs(false);

        for fs in [&fs_explicit, &fs_default] {
            let entry = fs.lookup(context(), ROOT_INODE, c"visible.txt").unwrap();
            let (handle, _) = fs
                .open(context(), entry.inode, false, LINUX_O_RDONLY)
                .unwrap();
            let handle = handle.unwrap();
            let mut writer = CaptureWriter { bytes: Vec::new() };
            fs.read(context(), entry.inode, handle, &mut writer, 64, 0, None, 0)
                .unwrap();
            assert_eq!(writer.bytes, b"hello world");
            fs.release(context(), entry.inode, 0, handle, false, false, None)
                .unwrap();

            let (dir_handle, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
            let entries = fs
                .readdir(context(), ROOT_INODE, dir_handle.unwrap(), 4096, 0)
                .unwrap();
            let names: Vec<_> = entries.iter().map(|e| e.name).collect();
            assert_eq!(names, vec![b".".as_slice(), b"..", b"visible.txt"]);
            assert_eq!(entries.len(), 3);
            // getattr on ROOT must succeed even when no policy is configured.
            fs.getattr(context(), ROOT_INODE, None).unwrap();
            fs.forget(context(), entry.inode, 1);
        }

        // Explicit byte-identical comparison of readdir names between the two configurations.
        let (_tmp_a, fs_a) = {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("a.txt");
            std::fs::write(&source, b"x").unwrap();
            let mut cfg = PassthroughConfig::default();
            cfg.mask_policy = None;
            let fs = SingleFileFs::new(source.clone(), "a.txt".to_string(), cfg).unwrap();
            fs.init(FsOptions::empty()).unwrap();
            (temp, fs)
        };
        let (_tmp_b, fs_b) = {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("a.txt");
            std::fs::write(&source, b"x").unwrap();
            let fs = SingleFileFs::new(
                source.clone(),
                "a.txt".to_string(),
                PassthroughConfig::default(),
            )
            .unwrap();
            fs.init(FsOptions::empty()).unwrap();
            (temp, fs)
        };
        let names_a = {
            let (h, _) = fs_a.opendir(context(), ROOT_INODE, 0).unwrap();
            let mut v: Vec<Vec<u8>> = fs_a
                .readdir(context(), ROOT_INODE, h.unwrap(), 4096, 0)
                .unwrap()
                .into_iter()
                .map(|e| e.name.to_vec())
                .collect();
            v.sort();
            v
        };
        let names_b = {
            let (h, _) = fs_b.opendir(context(), ROOT_INODE, 0).unwrap();
            let mut v: Vec<Vec<u8>> = fs_b
                .readdir(context(), ROOT_INODE, h.unwrap(), 4096, 0)
                .unwrap()
                .into_iter()
                .map(|e| e.name.to_vec())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names_a, names_b);
    }

    //----------------------------------------------------------------------------------------------
    // T2 [P1] masked_single_file_is_empty_dir — host-basename semantics
    //----------------------------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn t2_masked_single_file_is_empty_dir_host_basename() {
        use std::sync::Arc;
        // Host file is "secret.env", guest name is "config.env" (different) to prove that the
        // mask policy is evaluated against the HOST basename, not the guest name. See spec note:
        // "guest 'config.env' ≠ host 'secret.env', pattern on 'secret.env' still masks."
        let temp = tempfile::tempdir().unwrap();
        let host_path = temp.path().join("secret.env");
        std::fs::write(&host_path, b"super-secret").unwrap();

        let policy = Arc::new(policy_program(&["secret.env"], &[]));
        let fs = SingleFileFs::new(
            host_path.clone(),
            "config.env".to_string(),
            PassthroughConfig {
                mask_policy: Some(policy),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        // Lookup of the guest entry must be ENOENT when the host basename is masked.
        let err = match fs.lookup(context(), ROOT_INODE, c"config.env") {
            Ok(_) => panic!("masked lookup must be ENOENT"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(LINUX_ENOENT));

        // readdir must return ONLY [".", ".."] (empty synthetic mount), not the masked file.
        let (dir_handle, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let entries = fs
            .readdir(context(), ROOT_INODE, dir_handle.unwrap(), 4096, 0)
            .unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            vec![b".".as_slice(), b".."],
            "masked file must not appear in readdir"
        );
        assert_eq!(entries.len(), 2);

        // readdirplus must similarly return only dot entries.
        let (dir_handle2, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let plus = fs
            .readdirplus(context(), ROOT_INODE, dir_handle2.unwrap(), 4096, 0)
            .unwrap();
        assert_eq!(plus.len(), 2);
        assert_eq!(plus[0].0.name, b".");
        assert_eq!(plus[1].0.name, b"..");

        // getattr(ROOT) must remain accessible and must not panic.
        let (st, _) = fs.getattr(context(), ROOT_INODE, None).unwrap();
        assert_ne!(st.st_mode & S_IFDIR as u32, 0);

        // Offset handling on masked mount must still be correct (skip dots).
        let (dir_handle3, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let tail = fs
            .readdir(context(), ROOT_INODE, dir_handle3.unwrap(), 4096, 1)
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].name, b"..");
    }

    #[cfg(unix)]
    #[test]
    fn t2_masked_single_file_is_empty_dir_guest_equals_host() {
        use std::sync::Arc;
        // Variant where guest == host basename; both must be masked.
        let temp = tempfile::tempdir().unwrap();
        let host_path = temp.path().join("secret.env");
        std::fs::write(&host_path, b"super-secret").unwrap();

        let policy = Arc::new(policy_program(&["secret.env"], &[]));
        let fs = SingleFileFs::new(
            host_path.clone(),
            "secret.env".to_string(),
            PassthroughConfig {
                mask_policy: Some(policy),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let err = match fs.lookup(context(), ROOT_INODE, c"secret.env") {
            Ok(_) => panic!("masked lookup must be ENOENT"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(LINUX_ENOENT));

        let (dir_handle, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let entries = fs
            .readdir(context(), ROOT_INODE, dir_handle.unwrap(), 4096, 0)
            .unwrap();
        assert_eq!(entries.len(), 2);
        fs.getattr(context(), ROOT_INODE, None).unwrap();
    }

    //----------------------------------------------------------------------------------------------
    // T3 [P1] write_deny_on_file — writes.deny on host basename blocks WRONLY/RDWR, allows RDONLY
    //----------------------------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn t3_write_deny_on_file_blocks_write_allows_read() {
        use crate::backends::passthroughfs::mount_policy::ScopeKind;
        use std::sync::Arc;
        // Host file "data.txt" with contents "hello", guest name "data.txt".
        // Policy denies writes on host basename "data.txt" with writes.deny.
        let temp = tempfile::tempdir().unwrap();
        let host_path = temp.path().join("data.txt");
        std::fs::write(&host_path, b"hello").unwrap();

        let policy = Arc::new(write_program(
            &[],
            &[],
            &[("data.txt", ScopeKind::Workload, true)],
        ));
        let fs = SingleFileFs::new(
            host_path.clone(),
            "data.txt".to_string(),
            PassthroughConfig {
                readonly: false,
                mask_policy: Some(policy),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let entry = fs.lookup(context(), ROOT_INODE, c"data.txt").unwrap();

        // O_RDONLY must succeed and read must return bytes.
        let (ro_handle, _) = fs
            .open(context(), entry.inode, false, LINUX_O_RDONLY)
            .unwrap();
        let ro_handle = ro_handle.unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        fs.read(
            context(),
            entry.inode,
            ro_handle,
            &mut writer,
            64,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(writer.bytes, b"hello");
        fs.release(context(), entry.inode, 0, ro_handle, false, false, None)
            .unwrap();

        // O_WRONLY must be denied with EACCES.
        let err = fs
            .open(context(), entry.inode, false, LINUX_O_WRONLY)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(LINUX_EACCES));

        // O_RDWR must be denied with EACCES.
        let err = fs
            .open(context(), entry.inode, false, LINUX_O_RDWR)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(LINUX_EACCES));

        // Regression: same without policy — write succeeds.
        let temp2 = tempfile::tempdir().unwrap();
        let host2 = temp2.path().join("data.txt");
        std::fs::write(&host2, b"hello").unwrap();
        let fs2 = SingleFileFs::new(
            host2.clone(),
            "data.txt".to_string(),
            PassthroughConfig::default(),
        )
        .unwrap();
        fs2.init(FsOptions::empty()).unwrap();
        let entry2 = fs2.lookup(context(), ROOT_INODE, c"data.txt").unwrap();
        let (whandle, _) = fs2
            .open(context(), entry2.inode, false, LINUX_O_WRONLY)
            .unwrap();
        let whandle = whandle.unwrap();
        let mut reader = SliceReader::new(b" world");
        let n = fs2
            .write(
                context(),
                entry2.inode,
                whandle,
                &mut reader,
                6,
                5,
                None,
                false,
                false,
                0,
            )
            .unwrap();
        assert_eq!(n, 6);
        fs2.release(context(), entry2.inode, 0, whandle, false, false, None)
            .unwrap();
        // Verify readback.
        let (rhandle, _) = fs2
            .open(context(), entry2.inode, false, LINUX_O_RDONLY)
            .unwrap();
        let rhandle = rhandle.unwrap();
        let mut writer2 = CaptureWriter { bytes: Vec::new() };
        fs2.read(
            context(),
            entry2.inode,
            rhandle,
            &mut writer2,
            64,
            0,
            None,
            0,
        )
        .unwrap();
        assert_eq!(writer2.bytes, b"hello world");
        fs2.release(context(), entry2.inode, 0, rhandle, false, false, None)
            .unwrap();
        fs2.forget(context(), entry2.inode, 1);

        fs.forget(context(), entry.inode, 1);
    }

    #[cfg(unix)]
    #[test]
    fn t3_write_deny_host_basename_semantics_different_guest_name() {
        use crate::backends::passthroughfs::mount_policy::ScopeKind;
        use std::sync::Arc;
        // Prove host-basename semantics for writes.deny as well: host "data.txt",
        // guest "config.txt" — deny on "data.txt" must still block writes to "config.txt".
        let temp = tempfile::tempdir().unwrap();
        let host_path = temp.path().join("data.txt");
        std::fs::write(&host_path, b"hello").unwrap();
        let policy = Arc::new(write_program(
            &[],
            &[],
            &[("data.txt", ScopeKind::Workload, true)],
        ));
        let fs = SingleFileFs::new(
            host_path.clone(),
            "config.txt".to_string(),
            PassthroughConfig {
                readonly: false,
                mask_policy: Some(policy),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let entry = fs.lookup(context(), ROOT_INODE, c"config.txt").unwrap();
        // read allowed
        let (h, _) = fs
            .open(context(), entry.inode, false, LINUX_O_RDONLY)
            .unwrap();
        fs.release(context(), entry.inode, 0, h.unwrap(), false, false, None)
            .unwrap();
        // write denied
        let err = fs
            .open(context(), entry.inode, false, LINUX_O_WRONLY)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(LINUX_EACCES));
        fs.forget(context(), entry.inode, 1);
    }

    //----------------------------------------------------------------------------------------------
    // T5 [P2] quota+policy coexist on file mount — quota_bytes + mask_policy no-op
    //----------------------------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn t5_quota_and_policy_coexist_on_file_mount_no_interference() {
        use std::sync::Arc;
        // quota_bytes Some (1 MiB) + mask_policy Some with unrelated pattern "other.txt"
        // must remain no-op on the visible file: lookup succeeds, readdir 3 entries, etc.
        let temp = tempfile::tempdir().unwrap();
        let host_path = temp.path().join("visible.txt");
        std::fs::write(&host_path, b"visible content").unwrap();

        let policy = Arc::new(policy_program(&["other.txt"], &[]));
        let fs = SingleFileFs::new(
            host_path.clone(),
            "visible.txt".to_string(),
            PassthroughConfig {
                quota_bytes: Some(1 * 1024 * 1024),
                mask_policy: Some(policy),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let entry = fs.lookup(context(), ROOT_INODE, c"visible.txt").unwrap();

        let (dir_handle, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let entries = fs
            .readdir(context(), ROOT_INODE, dir_handle.unwrap(), 4096, 0)
            .unwrap();
        assert_eq!(entries.len(), 3);
        let names: Vec<_> = entries.iter().map(|e| e.name).collect();
        assert_eq!(names, vec![b".".as_slice(), b"..", b"visible.txt"]);

        // getattr ROOT ok
        fs.getattr(context(), ROOT_INODE, None).unwrap();
        // getattr file ok
        let (attr, _) = fs.getattr(context(), entry.inode, None).unwrap();
        assert!(attr.st_size > 0);

        // read succeeds
        let (handle, _) = fs
            .open(context(), entry.inode, false, LINUX_O_RDONLY)
            .unwrap();
        let handle = handle.unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        fs.read(context(), entry.inode, handle, &mut writer, 64, 0, None, 0)
            .unwrap();
        assert_eq!(writer.bytes, b"visible content");
        fs.release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();

        // write within quota must succeed (quota enforcement doesn't break policy no-op)
        let (whandle, _) = fs
            .open(context(), entry.inode, false, LINUX_O_WRONLY)
            .unwrap();
        let whandle = whandle.unwrap();
        let mut reader = SliceReader::new(b" appended");
        let n = fs
            .write(
                context(),
                entry.inode,
                whandle,
                &mut reader,
                9,
                15,
                None,
                false,
                false,
                0,
            )
            .unwrap();
        assert_eq!(n, 9);
        fs.release(context(), entry.inode, 0, whandle, false, false, None)
            .unwrap();

        // readdir still 3 after write
        let (dir_handle2, _) = fs.opendir(context(), ROOT_INODE, 0).unwrap();
        let entries2 = fs
            .readdir(context(), ROOT_INODE, dir_handle2.unwrap(), 4096, 0)
            .unwrap();
        assert_eq!(entries2.len(), 3);

        // lookup of unrelated masked name must still be ENOENT (guest only exposes visible.txt)
        // and unrelated pattern must not leak.
        let err = match fs.lookup(context(), ROOT_INODE, c"other.txt") {
            Ok(_) => panic!("other.txt lookup must be ENOENT"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(LINUX_ENOENT));

        fs.forget(context(), entry.inode, 1);
    }

    #[cfg(unix)]
    #[test]
    fn t5_quota_policy_noop_still_enforces_quota() {
        use std::sync::Arc;
        // Ensure quota is still enforced when policy is a no-op: write past limit -> ENOSPC.
        let temp = tempfile::tempdir().unwrap();
        let host_path = temp.path().join("visible.txt");
        std::fs::write(&host_path, b"hi").unwrap();
        let policy = Arc::new(policy_program(&["ghost.txt"], &[]));
        let limit = 1024u64;
        let fs = SingleFileFs::new(
            host_path.clone(),
            "visible.txt".to_string(),
            PassthroughConfig {
                quota_bytes: Some(limit),
                mask_policy: Some(policy),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let entry = fs.lookup(context(), ROOT_INODE, c"visible.txt").unwrap();
        let (handle, _) = fs
            .open(context(), entry.inode, false, LINUX_O_WRONLY)
            .unwrap();
        let handle = handle.unwrap();
        // Try to grow far beyond quota — should get ENOSPC.
        let big = vec![0u8; (limit + 1024) as usize];
        let mut reader = SliceReader::new(&big);
        let err = fs
            .write(
                context(),
                entry.inode,
                handle,
                &mut reader,
                big.len() as u32,
                0,
                None,
                false,
                false,
                0,
            )
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(LINUX_ENOSPC));
        fs.release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
        fs.forget(context(), entry.inode, 1);
    }
}
