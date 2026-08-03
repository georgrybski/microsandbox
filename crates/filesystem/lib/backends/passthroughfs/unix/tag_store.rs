//! Alias-scoped dynamic visibility tags (spec 22 §§10.4–10.5).

use std::{
    io,
    os::fd::{FromRawFd, RawFd},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use lru::LruCache;

use crate::backends::shared::inode_table::InodeAltKey;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CAPACITY: usize = 10_000;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Alias identity used by the policy tag store.
pub(crate) type TagKey = (u64, Vec<u8>);

/// An O_PATH-pinned host identity and the identity recorded when it was tagged.
pub(crate) struct TagValue {
    #[allow(dead_code)]
    pub(crate) file: std::fs::File,
    pub(crate) alt_key: InodeAltKey,
}

/// Bounded LRU store of guest-created or guest-written masked aliases.
pub(crate) struct TagStore {
    cache: Mutex<LruCache<TagKey, TagValue>>,
    exhausted: AtomicU64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TagStore {
    /// Create the spec 22 §10.4 bounded tag store.
    pub(crate) fn new() -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(CAPACITY).unwrap(),
            )),
            exhausted: AtomicU64::new(0),
        }
    }

    /// Test and touch an alias tag.
    pub(crate) fn contains(&self, parent: u64, name: &[u8]) -> bool {
        self.cache
            .lock()
            .unwrap()
            .get(&(parent, name.to_vec()))
            .is_some()
    }

    /// Return and touch the recorded identity for an alias.
    pub(crate) fn get_identity(&self, parent: u64, name: &[u8]) -> Option<InodeAltKey> {
        self.cache
            .lock()
            .unwrap()
            .get(&(parent, name.to_vec()))
            .map(|value| value.alt_key)
    }

    /// Pin `fd` and replace the alias tag.
    pub(crate) fn tag(
        &self,
        parent: u64,
        name: &[u8],
        fd: RawFd,
        alt_key: InodeAltKey,
    ) -> io::Result<()> {
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        let value = TagValue {
            file: unsafe { std::fs::File::from_raw_fd(dup) },
            alt_key,
        };
        let evicted = self
            .cache
            .lock()
            .unwrap()
            .push((parent, name.to_vec()), value);
        if evicted.is_some() {
            self.exhausted.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Remove one alias tag.
    pub(crate) fn evict(&self, parent: u64, name: &[u8]) {
        self.cache.lock().unwrap().pop(&(parent, name.to_vec()));
    }

    /// Remove all tags whose parent synthetic inode was forgotten.
    pub(crate) fn evict_parent(&self, parent: u64) {
        let keys: Vec<TagKey> = self
            .cache
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.0 == parent)
            .map(|(key, _)| key.clone())
            .collect();
        let mut cache = self.cache.lock().unwrap();
        for key in keys {
            cache.pop(&key);
        }
    }

    /// Return the number of LRU-capacity evictions.
    #[allow(dead_code)]
    pub(crate) fn evictions_exhausted(&self) -> u64 {
        self.exhausted.load(Ordering::Relaxed)
    }

    /// Drop every retained O_PATH descriptor.
    pub(crate) fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn lru_eviction_and_lifecycle() {
        let store = TagStore::new();
        let file = tempfile::tempfile().unwrap();
        let key = InodeAltKey::new(1, 2, 3);
        for index in 0..=CAPACITY {
            store
                .tag(1, format!("{index}").as_bytes(), file.as_raw_fd(), key)
                .unwrap();
        }
        assert!(!store.contains(1, b"0"));
        assert_eq!(store.evictions_exhausted(), 1);
        store.evict(1, b"1");
        assert!(!store.contains(1, b"1"));
        store.tag(7, b"child", file.as_raw_fd(), key).unwrap();
        store.evict_parent(7);
        assert!(!store.contains(7, b"child"));
        store.clear();
        assert!(!store.contains(1, b"2"));
    }
}
