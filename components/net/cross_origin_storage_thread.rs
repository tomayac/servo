/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The Cross-Origin Storage registry
//! (<https://wicg.github.io/cross-origin-storage/#cos-entries>): shared
//! across every script thread that talks to this resource thread (via
//! `Arc<RwLock<...>>`, following `FileManager`'s shape in
//! `filemanager_thread.rs`), and persisted to disk under `config_dir`
//! using the same `servo_base::read_json_from_file` / `write_json_to_file`
//! helpers already used for the cookie jar, HSTS list, and auth cache in
//! `resource_thread.rs`.
//!
//! `script::dom::crossoriginstorage::registry` is a thin IPC client for
//! this service, not the source of truth; the actual spec algorithms
//! (entry state machine, origins scoping, storing-origins bookkeeping,
//! availability gating, visibility-upgrade merging, hash verification)
//! live here.
//!
//! Explicitly NOT real:
//! - No Public Hash List (wildcard entries fail closed).
//! - No GREASE'ing.
//! - No `maximum origins list length` or per-origin write quota
//!   enforcement.
//! - No eviction of abandoned Pending entries.
//! - Persistence is whole-registry-metadata read-on-startup /
//!   write-on-every-mutation JSON (see below for why entry *bytes* are
//!   not part of that), not incremental or transactional; two resource
//!   threads racing to write the same file (which should not normally
//!   happen -- there is one resource thread per Servo instance) would not
//!   be safe, but that is not a realistic configuration here.
//!
//! `SameSiteOnly` disclosure uses `net_traits::pub_domains::is_same_site`
//! (Public Suffix List-backed eTLD+1 comparison, the same helper the
//! cookie jar uses for `SameSite`): `https://a.example.com` and
//! `https://b.example.com` are same-site (same registrable domain,
//! different origins), while `https://example.com` and
//! `https://example.co.uk` are not, despite superficially similar names.
//!
//! Entry bytes live in their own per-entry file under
//! `config_dir/cos_entries/`, not inline in the registry JSON: `persist()`
//! serializes and writes the *entire* registry metadata on every single
//! mutation (every `create` and every `close()`), so embedding entry
//! content there would make every unrelated future write's cost scale
//! with the total size of every large entry ever stored, unboundedly.
//! Keeping bytes in their own file makes `persist()`'s cost proportional
//! to the number of entries, not their total size, and means writing one
//! entry never implies rewriting any other one.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::digest;
use log::warn;
use net_traits::cross_origin_storage_thread::{
    CosHash, CosReadOutcome, CosThreadMsg, RequestedOrigins,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use servo_url::ImmutableOrigin;

const PERSISTED_FILENAME: &str = "cross_origin_storage_registry.json";
const ENTRY_BYTES_DIR: &str = "cos_entries";

/// Path of the on-disk file holding one entry's raw bytes. `key` is
/// `registry_key()`'s `"ALGORITHM:hex_value"` form; `:` is replaced since
/// it is not a safe filename character on every platform this needs to
/// run on.
fn entry_bytes_path(config_dir: &Path, key: &str) -> PathBuf {
    config_dir
        .join(ENTRY_BYTES_DIR)
        .join(format!("{}.bin", key.replace(':', "_")))
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
enum CosEntryState {
    Pending,
    Written,
}

#[derive(Clone, Deserialize, Serialize)]
enum CosOrigins {
    Wildcard,
    List(Vec<ImmutableOrigin>),
    SameSiteOnly,
}

#[derive(Clone, Deserialize, Serialize)]
struct StoredEntryBytes {
    /// Not part of the registry JSON; see this module's doc comment.
    /// Populated from its own per-entry file, either right after a
    /// successful `verify_and_store` (in memory only, no re-read needed)
    /// or by `CrossOriginStorageStore::new()` on startup.
    #[serde(skip)]
    bytes: Vec<u8>,
    type_string: String,
}

#[derive(Deserialize, Serialize)]
struct CosEntry {
    bytes: Option<StoredEntryBytes>,
    state: CosEntryState,
    origins: CosOrigins,
    storing_origins: HashSet<ImmutableOrigin>,
}

/// The persisted (and in-memory) registry contents. `HashMap` keys here
/// are plain `String`s (the hash's normalized `"ALGORITHM:value"` form),
/// not the `(String, String)` tuple used internally elsewhere in this
/// codebase's COS work: `serde_json` cannot serialize a tuple as a JSON
/// object key, only a plain string.
#[derive(Default, Deserialize, Serialize)]
struct CosRegistryData {
    entries: HashMap<String, CosEntry>,
}

fn registry_key(hash: &CosHash) -> String {
    let (algorithm, value) = hash.normalized_key();
    format!("{algorithm}:{value}")
}

#[derive(Clone)]
pub struct CrossOriginStorageStore {
    data: Arc<RwLock<CosRegistryData>>,
    config_dir: Option<PathBuf>,
}

impl CrossOriginStorageStore {
    pub fn new(config_dir: Option<PathBuf>) -> Self {
        let mut data = CosRegistryData::default();
        if let Some(dir) = &config_dir {
            servo_base::read_json_from_file(&mut data, dir, PERSISTED_FILENAME);
            // The registry JSON only records *that* a written entry has
            // bytes (via `Some(StoredEntryBytes)`), not the bytes
            // themselves -- load each one back from its own file now.
            for (key, entry) in data.entries.iter_mut() {
                if entry.bytes.is_none() {
                    continue;
                }
                match std::fs::read(entry_bytes_path(dir, key)) {
                    Ok(bytes) => {
                        if let Some(stored) = entry.bytes.as_mut() {
                            stored.bytes = bytes;
                        }
                    },
                    Err(err) => {
                        warn!(
                            "Could not load Cross-Origin Storage entry bytes for \
                             {key} from disk ({err}); treating this entry as if \
                             it were never written."
                        );
                        entry.bytes = None;
                    },
                }
            }
        }
        CrossOriginStorageStore {
            data: Arc::new(RwLock::new(data)),
            config_dir,
        }
    }

    /// Persists registry *metadata* (state, origins, storing-origins) --
    /// deliberately not entry bytes; see this module's doc comment.
    fn persist(&self, data: &CosRegistryData) {
        if let Some(dir) = &self.config_dir {
            servo_base::write_json_to_file(data, dir, PERSISTED_FILENAME);
        }
    }

    /// Persists one entry's raw bytes to its own file. Called instead of
    /// (not in addition to some inline JSON representation of) storing
    /// them as part of `persist()`'s registry-wide write; see this
    /// module's doc comment for why.
    fn persist_entry_bytes(&self, key: &str, bytes: &[u8]) {
        let Some(dir) = &self.config_dir else {
            return;
        };
        let path = entry_bytes_path(dir, key);
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                warn!("Could not create {}: {err}", parent.display());
                return;
            }
        }
        if let Err(err) = std::fs::write(&path, bytes) {
            warn!("Could not write Cross-Origin Storage entry bytes to {}: {err}", path.display());
        }
    }

    /// Message handler, mirroring `FileManager::handle`.
    pub fn handle(&self, msg: CosThreadMsg) {
        match msg {
            CosThreadMsg::Read(hash, origin, response_sender) => {
                let outcome = self.complete_a_read_request(&hash, &origin);
                let _ = response_sender.send(outcome);
            },
            CosThreadMsg::Create(hash, requested_origins) => {
                self.complete_a_create_request(&hash, requested_origins);
            },
            CosThreadMsg::VerifyAndStore(hash, bytes, type_string, origin, requested_origins, response_sender) => {
                let result =
                    self.verify_and_store(&hash, bytes, type_string, origin, requested_origins);
                let _ = response_sender.send(result);
            },
        }
    }

    /// <https://wicg.github.io/cross-origin-storage/#complete-a-read-request>
    fn complete_a_read_request(&self, hash: &CosHash, origin: &ImmutableOrigin) -> CosReadOutcome {
        let data = self.data.read();
        let Some(entry) = data.entries.get(&registry_key(hash)) else {
            return CosReadOutcome::NotFound;
        };

        if entry.state == CosEntryState::Pending {
            return CosReadOutcome::PendingWrite;
        }

        if !self.apply_availability_gating(entry, origin) {
            return CosReadOutcome::NotFound;
        }

        match &entry.bytes {
            Some(bytes) => CosReadOutcome::Found {
                bytes: bytes.bytes.clone(),
                type_string: bytes.type_string.clone(),
            },
            None => CosReadOutcome::NotFound,
        }
    }

    /// <https://wicg.github.io/cross-origin-storage/#complete-a-create-request>
    fn complete_a_create_request(&self, hash: &CosHash, requested_origins: Option<RequestedOrigins>) {
        let normalized = match requested_origins {
            None => CosOrigins::SameSiteOnly,
            Some(RequestedOrigins::Wildcard) => CosOrigins::Wildcard,
            Some(RequestedOrigins::List(origins)) => CosOrigins::List(origins),
        };

        let mut data = self.data.write();
        data.entries.entry(registry_key(hash)).or_insert_with(|| CosEntry {
            bytes: None,
            state: CosEntryState::Pending,
            origins: normalized,
            storing_origins: HashSet::new(),
        });
        self.persist(&data);
    }

    /// <https://wicg.github.io/cross-origin-storage/#verify-and-store>
    fn verify_and_store(
        &self,
        hash: &CosHash,
        bytes: Vec<u8>,
        type_string: String,
        origin: ImmutableOrigin,
        requested_origins: Option<RequestedOrigins>,
    ) -> Result<(), ()> {
        let Some(computed_hex) = compute_hex_digest(&hash.algorithm, &bytes) else {
            return Err(());
        };
        if computed_hex != hash.value.to_ascii_lowercase() {
            return Err(());
        }

        let key = registry_key(hash);
        // Write the (possibly large) bytes to their own file before
        // taking the registry lock, so the lock is held only for cheap
        // metadata bookkeeping below, not for however long this disk
        // write takes.
        self.persist_entry_bytes(&key, &bytes);

        let mut data = self.data.write();
        let entry = data
            .entries
            .entry(key)
            .or_insert_with(|| CosEntry {
                bytes: None,
                state: CosEntryState::Pending,
                origins: CosOrigins::SameSiteOnly,
                storing_origins: HashSet::new(),
            });

        entry.bytes = Some(StoredEntryBytes { bytes, type_string });
        entry.state = CosEntryState::Written;
        entry.storing_origins.insert(origin);
        upgrade_resource_visibility(entry, requested_origins);
        self.persist(&data);

        Ok(())
    }

    /// <https://wicg.github.io/cross-origin-storage/#apply-availability-gating>
    /// Simplified: GREASE'ing is not implemented; see this module's doc
    /// comment.
    fn apply_availability_gating(&self, entry: &CosEntry, origin: &ImmutableOrigin) -> bool {
        determine_cos_disclosure(entry, origin)
    }
}

/// <https://wicg.github.io/cross-origin-storage/#determine-cos-disclosure>
fn determine_cos_disclosure(entry: &CosEntry, origin: &ImmutableOrigin) -> bool {
    if entry.storing_origins.contains(origin) {
        return true;
    }

    match &entry.origins {
        CosOrigins::Wildcard => is_on_public_hash_list(),
        CosOrigins::List(list) => list.contains(origin),
        CosOrigins::SameSiteOnly => entry
            .storing_origins
            .iter()
            .any(|storing_origin| net_traits::pub_domains::is_same_site(origin, storing_origin)),
    }
}

/// Always `false`; see this module's doc comment.
fn is_on_public_hash_list() -> bool {
    false
}

/// <https://wicg.github.io/cross-origin-storage/#upgrade-resource-visibility>
fn upgrade_resource_visibility(entry: &mut CosEntry, requested_origins: Option<RequestedOrigins>) {
    let Some(requested) = requested_origins else {
        return;
    };

    if matches!(entry.origins, CosOrigins::Wildcard) {
        return;
    }

    match requested {
        RequestedOrigins::Wildcard => {
            entry.origins = CosOrigins::Wildcard;
        },
        RequestedOrigins::List(candidates) => match &mut entry.origins {
            CosOrigins::SameSiteOnly => {
                entry.origins = CosOrigins::List(candidates);
            },
            CosOrigins::List(existing) => {
                for candidate in candidates {
                    if !existing.contains(&candidate) {
                        existing.push(candidate);
                    }
                }
            },
            CosOrigins::Wildcard => unreachable!("handled by the early return above"),
        },
    }
}

fn compute_hex_digest(algorithm: &str, bytes: &[u8]) -> Option<String> {
    let computed = match algorithm.to_ascii_uppercase().as_str() {
        "SHA-1" => digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, bytes),
        "SHA-256" => digest::digest(&digest::SHA256, bytes),
        "SHA-384" => digest::digest(&digest::SHA384, bytes),
        "SHA-512" => digest::digest(&digest::SHA512, bytes),
        _ => return None,
    };
    Some(
        computed
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
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

    fn origin(url: &str) -> ImmutableOrigin {
        ImmutableOrigin::new(&url::Url::parse(url).unwrap())
    }

    /// `config_dir: None` throughout: these tests exercise the in-memory
    /// algorithms only, not the persistence path.
    fn store() -> CrossOriginStorageStore {
        CrossOriginStorageStore::new(None)
    }

    #[test]
    fn unknown_hash_reads_as_not_found() {
        let store = store();
        let h = hash("SHA-256", &"a".repeat(64));
        let o = origin("https://example.com");
        assert!(matches!(
            store.complete_a_read_request(&h, &o),
            CosReadOutcome::NotFound
        ));
    }

    #[test]
    fn write_then_read_by_storing_origin_succeeds() {
        let store = store();
        let bytes = b"hello cos".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");

        assert!(
            store
                .verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None)
                .is_ok()
        );

        match store.complete_a_read_request(&h, &writer) {
            CosReadOutcome::Found { bytes: found, .. } => assert_eq!(found, bytes),
            _ => panic!("expected the storing origin to read its own write back"),
        }
    }

    #[test]
    fn write_rejected_on_hash_mismatch() {
        let store = store();
        let h = hash("SHA-256", &"0".repeat(64));
        let writer = origin("https://writer.example");
        assert!(
            store
                .verify_and_store(&h, b"wrong bytes".to_vec(), "text/plain".to_owned(), writer, None)
                .is_err()
        );
    }

    #[test]
    fn same_site_only_entry_is_not_readable_by_a_different_origin() {
        let store = store();
        let bytes = b"same-site-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let other = origin("https://other.example");

        store
            .verify_and_store(&h, bytes, "text/plain".to_owned(), writer, None)
            .unwrap();

        assert!(matches!(
            store.complete_a_read_request(&h, &other),
            CosReadOutcome::NotFound
        ));
    }

    #[test]
    fn same_site_only_entry_is_readable_by_a_different_origin_on_the_same_registrable_domain() {
        // Two different subdomains of the same registrable domain are
        // same-site despite being different origins.
        let store = store();
        let bytes = b"same-site-subdomains".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example.com");
        let reader = origin("https://reader.example.com");

        store
            .verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer, None)
            .unwrap();

        match store.complete_a_read_request(&h, &reader) {
            CosReadOutcome::Found { bytes: found, .. } => assert_eq!(found, bytes),
            _ => panic!("expected a different-origin, same-registrable-domain reader to succeed"),
        }
    }

    #[test]
    fn same_site_only_entry_is_not_readable_across_different_registrable_domains() {
        // Same host suffix ("example.com" and "example.co.uk" both end in
        // similar-looking labels), but genuinely different registrable
        // domains -- must not be treated as same-site.
        let store = store();
        let bytes = b"different-registrable-domains".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://example.com");
        let other = origin("https://example.co.uk");

        store
            .verify_and_store(&h, bytes, "text/plain".to_owned(), writer, None)
            .unwrap();

        assert!(matches!(
            store.complete_a_read_request(&h, &other),
            CosReadOutcome::NotFound
        ));
    }

    #[test]
    fn list_scoped_entry_is_readable_by_a_listed_origin() {
        let store = store();
        let bytes = b"list-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let listed = origin("https://listed.example");

        store
            .verify_and_store(
                &h,
                bytes,
                "text/plain".to_owned(),
                writer,
                Some(RequestedOrigins::List(vec![listed.clone()])),
            )
            .unwrap();

        assert!(matches!(
            store.complete_a_read_request(&h, &listed),
            CosReadOutcome::Found { .. }
        ));
    }

    #[test]
    fn wildcard_entry_is_not_readable_by_an_outside_origin_without_a_phl() {
        let store = store();
        let bytes = b"wildcard-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let outsider = origin("https://outsider.example");

        store
            .verify_and_store(
                &h,
                bytes,
                "text/plain".to_owned(),
                writer,
                Some(RequestedOrigins::Wildcard),
            )
            .unwrap();

        // Fails closed: no PHL is implemented, so a "*"-scoped entry can
        // never actually be disclosed outside its storing origins today.
        assert!(matches!(
            store.complete_a_read_request(&h, &outsider),
            CosReadOutcome::NotFound
        ));
    }

    #[test]
    fn visibility_upgrade_never_downgrades_from_wildcard() {
        let store = store();
        let bytes = b"upgrade-test".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");

        store
            .verify_and_store(
                &h,
                bytes.clone(),
                "text/plain".to_owned(),
                writer.clone(),
                Some(RequestedOrigins::Wildcard),
            )
            .unwrap();

        let second_writer = origin("https://second-writer.example");
        store
            .verify_and_store(
                &h,
                bytes,
                "text/plain".to_owned(),
                second_writer,
                Some(RequestedOrigins::List(vec![origin("https://narrow.example")])),
            )
            .unwrap();

        let data = store.data.read();
        let entry = data.entries.get(&registry_key(&h)).unwrap();
        assert!(matches!(entry.origins, CosOrigins::Wildcard));
    }

    #[test]
    fn persists_across_store_instances_with_the_same_config_dir() {
        let dir = std::env::temp_dir().join(format!(
            "servo-cos-registry-test-{}",
            uuid_like_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let bytes = b"persisted".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");

        {
            let store = CrossOriginStorageStore::new(Some(dir.clone()));
            store
                .verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None)
                .unwrap();
        }

        // A fresh store pointed at the same config_dir should load what
        // the previous instance persisted, without any write happening in
        // between -- this is the "survives a restart" property.
        let reloaded = CrossOriginStorageStore::new(Some(dir.clone()));
        match reloaded.complete_a_read_request(&h, &writer) {
            CosReadOutcome::Found { bytes: found, .. } => assert_eq!(found, bytes),
            _ => panic!("expected the reloaded store to have the persisted entry"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cheap, dependency-free unique-ish suffix for a temp test directory
    /// name; not a real UUID, just needs to not collide across parallel
    /// test runs.
    fn uuid_like_suffix() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
