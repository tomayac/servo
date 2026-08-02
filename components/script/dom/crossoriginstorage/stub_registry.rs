/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! A process-local, in-memory, non-persistent stand-in for the real
//! Cross-Origin Storage registry
//! (<https://wicg.github.io/cross-origin-storage/#cos-entries>).
//!
//! This exists ONLY so that `requestFileHandle()` and
//! `FileSystemFileHandle::getFile()` can be exercised end to end while the
//! real registry -- which needs to be profile-scoped, persisted, shared
//! across script threads and processes, and subject to `origins` scoping,
//! availability gating, Public Hash List membership, GREASE'ing, and
//! storing-origins bookkeeping -- is built.
//!
//! Concretely, this stub:
//! - is `thread_local!`, so entries seeded from one script thread are not
//!   visible to requests from another. It is not even same-origin shared in
//!   any meaningful sense, let alone cross-origin;
//! - does not persist across navigations, tabs, or restarts;
//! - implements none of `origins` scoping, availability gating, the Public
//!   Hash List check, GREASE'ing, or storing-origins bookkeeping -- every
//!   entry it holds is unconditionally readable by any caller that knows
//!   the hash, which is not spec-conformant;
//! - has no write path yet: `CrossOriginStorageManager::RequestFileHandle`
//!   does not implement `options.create`, so entries can currently only be
//!   seeded by test code (`seed_for_test`), never by script.
//!
//! Do not build further Cross-Origin Storage functionality on top of this
//! module without replacing it with the real registry first.

use std::cell::RefCell;
use std::collections::HashMap;

use super::hash::CosHash;

/// A stand-in for a written [COS
/// entry](https://wicg.github.io/cross-origin-storage/#cos-entry)'s bytes.
/// Deliberately a plain, `Clone`-able struct of our own rather than
/// `servo_constellation_traits::BlobImpl` (which does not implement
/// `Clone`, by design: each `BlobImpl` carries its own identity via
/// `BlobId`). Callers construct a fresh `BlobImpl::new_from_bytes(...)` per
/// lookup instead.
#[derive(Clone)]
pub(crate) struct StubCosEntryBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) type_string: String,
}

thread_local! {
    static REGISTRY: RefCell<HashMap<(String, String), StubCosEntryBytes>> =
        RefCell::new(HashMap::new());
}

/// Look up a stub entry by its normalized hash key. Returns `None` for any
/// hash not previously seeded, which is the correct outcome for an empty
/// registry, but is not by itself evidence that the real spec's
/// `NotFoundError` semantics (see
/// <https://wicg.github.io/cross-origin-storage/#availability-gating>) are
/// implemented; there is currently nothing here to gate.
pub(crate) fn get(hash: &CosHash) -> Option<StubCosEntryBytes> {
    REGISTRY.with(|registry| registry.borrow().get(&hash.normalized_key()).cloned())
}

#[cfg(test)]
pub(crate) fn seed_for_test(hash: &CosHash, entry: StubCosEntryBytes) {
    REGISTRY.with(|registry| {
        registry.borrow_mut().insert(hash.normalized_key(), entry);
    });
}

#[cfg(test)]
pub(crate) fn clear_for_test() {
    REGISTRY.with(|registry| registry.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(algorithm: &str, value: &str) -> CosHash {
        CosHash {
            algorithm: algorithm.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn unknown_hash_is_absent() {
        clear_for_test();
        let h = hash("SHA-256", "a".repeat(64).as_str());
        assert!(get(&h).is_none());
    }

    #[test]
    fn seeded_hash_is_found_and_lookup_is_algorithm_case_insensitive() {
        clear_for_test();
        let value = "b".repeat(64);
        let h = hash("SHA-256", &value);
        seed_for_test(
            &h,
            StubCosEntryBytes {
                bytes: vec![1, 2, 3],
                type_string: "application/octet-stream".to_owned(),
            },
        );

        let lookup_lowercase = hash("sha-256", &value);
        let found = get(&lookup_lowercase).expect("entry should be found");
        assert_eq!(found.bytes, vec![1, 2, 3]);
    }
}
