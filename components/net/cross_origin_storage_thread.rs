/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The Cross-Origin Storage registry
//! (<https://wicg.github.io/cross-origin-storage/#cos-entries>), for real
//! this time: shared across every script thread that talks to this
//! resource thread (via `Arc<RwLock<...>>`, following `FileManager`'s
//! shape in `filemanager_thread.rs`), and persisted to disk under
//! `config_dir` using the same `servo_base::read_json_from_file` /
//! `write_json_to_file` helpers already used for the cookie jar, HSTS
//! list, and auth cache in `resource_thread.rs`.
//!
//! This replaces the earlier, `thread_local!`-based
//! `script::dom::crossoriginstorage::registry`, which is now a thin IPC
//! client for this service instead of the source of truth. The actual
//! spec algorithms (entry state machine, origins scoping, storing-origins
//! bookkeeping, availability gating, visibility-upgrade merging, hash
//! verification) are unchanged from that earlier version; only where they
//! run and how they're reached changed.
//!
//! Still explicitly NOT real, same as before:
//! - No Public Hash List (wildcard entries fail closed).
//! - No GREASE'ing.
//! - "Same site" approximated as same-origin.
//! - No `maximum origins list length` or per-origin write quota
//!   enforcement.
//! - No eviction of abandoned Pending entries.
//! - Persistence is whole-registry read-on-startup /
//!   write-on-every-mutation JSON, not incremental or transactional; two
//!   resource threads racing to write the same file (which should not
//!   normally happen -- there is one resource thread per Servo instance)
//!   would not be safe, but that is not a realistic configuration here.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use aws_lc_rs::digest;
use net_traits::cross_origin_storage_thread::{
    CosHash, CosReadOutcome, CosThreadMsg, RequestedOrigins,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use servo_url::ImmutableOrigin;

const PERSISTED_FILENAME: &str = "cross_origin_storage_registry.json";

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
        }
        CrossOriginStorageStore {
            data: Arc::new(RwLock::new(data)),
            config_dir,
        }
    }

    fn persist(&self, data: &CosRegistryData) {
        if let Some(dir) = &self.config_dir {
            servo_base::write_json_to_file(data, dir, PERSISTED_FILENAME);
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

        let mut data = self.data.write();
        let entry = data
            .entries
            .entry(registry_key(hash))
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
            .any(|storing_origin| is_same_site_approximation(origin, storing_origin)),
    }
}

/// Always `false`; see this module's doc comment.
fn is_on_public_hash_list() -> bool {
    false
}

/// See this module's doc comment: same-origin, not real same-site.
fn is_same_site_approximation(a: &ImmutableOrigin, b: &ImmutableOrigin) -> bool {
    a == b
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
