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
//! - No `maximum origins list length` or per-origin write quota
//!   enforcement.
//! - Persistence is whole-registry-metadata read-on-startup /
//!   write-on-every-mutation JSON (see below for why entry *bytes* are
//!   not part of that), not incremental or transactional; two resource
//!   threads racing to write the same file (which should not normally
//!   happen -- there is one resource thread per Servo instance) would not
//!   be safe, but that is not a realistic configuration here.
//!
//! `Wildcard`-scoped (`origins: '*'`) disclosure uses the real Public
//! Hash List (PHL): `net_traits::public_hash_list::is_hex_digest_on_public_hash_list`,
//! a bundled, sorted-for-binary-search snapshot of
//! <https://github.com/tomayac/public-hash-list> (refreshed by
//! `./mach update-public-hash-list`, also run weekly in CI -- see that
//! module's doc comment). A hash not on the list still fails closed,
//! same as before this was wired up; the difference is that a hash *on*
//! the list is now actually disclosed instead of every wildcard-scoped
//! entry being unconditionally hidden from non-storing origins.
//!
//! `Wildcard`-scoped entries that pass the PHL check above are also
//! subject to GREASE'ing: `should_grease` occasionally reports one as
//! absent anyway, at `GREASE_PROBABILITY`, and only when its stored
//! bytes are under `GREASE_MAX_SIZE_BYTES` (never for large entries,
//! where a spurious re-download would be expensive and itself
//! observable -- see `should_grease`'s doc comment).
//!
//! Every `complete a read request` call is also a probe (per the
//! explainer's own framing: "Each call to `requestFileHandle()` can be
//! considered a probe"), since its `Found`/`NotFound`/`PendingWrite`
//! outcome is directly observable by the calling script -- an origin
//! could otherwise brute-force many hashes to fingerprint what is
//! cross-origin-cached. `consume_probe_token` rate-limits this per
//! requesting origin with a token bucket (see its doc comment for the
//! capacity/refill numbers and reasoning); over budget, the call is
//! answered with `NotFound` the same way GREASE'ing lies, so hitting the
//! limit is not itself an observable signal. `complete_a_create_request`
//! is deliberately NOT budgeted the same way: it has no return value at
//! all (see its own doc comment), so it carries no directly observable
//! signal for an origin to probe with today.
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
//!
//! A `Pending` entry (created by `complete a create request`, before the
//! matching `close()`/`verify_and_store` ever runs) can be abandoned:
//! explicitly, via `FileSystemWritableFileStream.abort()`
//! (`CosThreadMsg::AbandonPendingWrite`, handled by
//! `abandon_pending_write` below, removes it immediately), or silently, by
//! a page navigating away or a stream simply never being closed or
//! aborted at all (no signal reaches this thread in that case). The
//! second kind is handled by `PENDING_ENTRY_STALE_AFTER_SECS`: a `Pending`
//! entry older than that is treated as absent by
//! `complete_a_read_request` (so a reader is not permanently stuck seeing
//! `PendingWrite`) and is replaced by a fresh one by
//! `complete_a_create_request` (so a new write attempt for the same hash
//! is not permanently blocked either). A `Pending` entry that is still
//! within the staleness window is left alone by both -- this is also the
//! ordinary, expected shape of two genuinely concurrent writes for the
//! same hash racing each other, not just the abandoned case.
//!
//! `CosOrigins::List`'s `Vec<ImmutableOrigin>` doubles as an LRU list:
//! order *is* the recency signal (front = least-recently-used, back =
//! most-recently-used), so no separate timestamps are needed. A
//! successful read by a listed origin (`touch_listed_origin`, called
//! from `complete_a_read_request`) moves it to the back. Merging a new
//! call's candidates in (`merge_origins_list`, called from
//! `upgrade_resource_visibility`) appends genuinely new ones at the back
//! and, if that would exceed `net_traits::cross_origin_storage_thread::MAX_ORIGINS_LIST_LENGTH`,
//! evicts from the front until it fits again -- silently, per that
//! constant's doc comment, not as an error. An already-present candidate
//! being re-declared in a merge does *not* move it: only an actual read
//! refreshes recency, so a writer can't keep a dormant origin artificially
//! "alive" just by repeatedly re-declaring it without it ever being used.
//! The touch itself is not separately persisted to disk (seeing this
//! module's doc comment above on `persist()`'s whole-registry write cost
//! -- doing so on every single read would mean a disk write per read, not
//! just per mutation); it piggybacks on whatever the next real mutation's
//! persist happens to be, so exact recency ordering is only guaranteed
//! within one running session, falling back to the last-persisted order
//! across a restart. That is an acceptable soft-fairness degradation, not
//! a correctness issue: the length cap itself is still always enforced
//! regardless of persistence timing.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use log::warn;
use net_traits::cross_origin_storage_thread::{
    CosHash, CosReadOutcome, CosThreadMsg, MAX_ORIGINS_LIST_LENGTH, RequestedOrigins,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use servo_url::ImmutableOrigin;

const PERSISTED_FILENAME: &str = "cross_origin_storage_registry.json";
const ENTRY_BYTES_DIR: &str = "cos_entries";

/// How long a `Pending` entry is left alone before `complete_a_read_request`
/// and `complete_a_create_request` treat it as abandoned; see this
/// module's doc comment.
const PENDING_ENTRY_STALE_AFTER_SECS: u64 = 5 * 60;

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Path of the on-disk file holding one entry's raw bytes. `key` is
/// `registry_key()`'s `"ALGORITHM:hex_value"` form; `:` is replaced since
/// it is not a safe filename character on every platform this needs to
/// run on.
fn entry_bytes_path(config_dir: &Path, key: &str) -> PathBuf {
    config_dir
        .join(ENTRY_BYTES_DIR)
        .join(format!("{}.bin", key.replace(':', "_")))
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
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
    /// Seconds since the Unix epoch when this entry was created (i.e. when
    /// it became `Pending`). Only consulted while `state` is still
    /// `Pending`; see `is_stale_pending` and this module's doc comment.
    pending_since_unix_secs: u64,
}

/// Whether `entry` is a `Pending` entry old enough to be treated as
/// abandoned; see this module's doc comment.
fn is_stale_pending(entry: &CosEntry) -> bool {
    entry.state == CosEntryState::Pending &&
        unix_now_secs().saturating_sub(entry.pending_since_unix_secs) > PENDING_ENTRY_STALE_AFTER_SECS
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

/// Maximum number of read probes a single requesting origin can make in
/// a burst before `consume_probe_token` starts denying them; see that
/// method's doc comment for the full reasoning. Sized around large
/// sharded-AI-model loading (some architectures ship weights as ~25 MiB
/// shards), where a legitimate page may need to probe hundreds of hashes
/// in one go: 2000 covers a ~50 GiB model's worth of 25 MiB shards in a
/// single burst, well past any realistically deployed web model size,
/// while still being small enough to bound worst-case memory for the
/// per-origin token map.
const PROBE_BUDGET_CAPACITY: f64 = 2000.0;

/// Steady-state refill rate for `PROBE_BUDGET_CAPACITY`, in tokens per
/// second. Fast enough that a legitimate page's staggered probes (one
/// per shard, as they're needed) never notice the limit even after
/// exhausting a burst, slow enough that an attacker trying to enumerate
/// many hashes per second to fingerprint a victim is throttled to a
/// trickle indefinitely rather than just waiting out one cooldown.
const PROBE_BUDGET_REFILL_PER_SECOND: f64 = 20.0;

/// One requesting origin's read-probe rate-limit state; see
/// `consume_probe_token`.
struct ProbeBudget {
    /// Current token balance. `f64`, not an integer count, since refill
    /// accrues continuously (a fraction of a token per elapsed
    /// millisecond) rather than in discrete per-second ticks -- this
    /// avoids the token bucket needing its own timer/task, since it can
    /// just compute elapsed time lazily on each probe instead.
    tokens: f64,
    last_refill: Instant,
}

#[derive(Clone)]
pub struct CrossOriginStorageStore {
    data: Arc<RwLock<CosRegistryData>>,
    config_dir: Option<PathBuf>,
    /// Read-probe rate-limit state per requesting origin; see
    /// `consume_probe_token`. Deliberately not part of `CosRegistryData`:
    /// this is a rate limiter, not registry content, and resetting it on
    /// restart (rather than persisting it) is the correct behavior for
    /// one, not a bug -- an origin should not be penalized across
    /// browser restarts for probing before a restart.
    probe_budgets: Arc<Mutex<HashMap<ImmutableOrigin, ProbeBudget>>>,
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
            probe_budgets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// <https://wicg.github.io/cross-origin-storage/#read-requests> notes
    /// user agents "are expected to implement safeguards against such
    /// attacks, for example, by limiting the number of probes"; this is
    /// that safeguard, implemented as a token bucket
    /// (<https://en.wikipedia.org/wiki/Token_bucket>) per requesting
    /// origin: `PROBE_BUDGET_CAPACITY` tokens available in a burst,
    /// refilling at `PROBE_BUDGET_REFILL_PER_SECOND` tokens/second
    /// thereafter. Returns whether a token was available (the probe may
    /// proceed) or the origin is over budget (the caller should lie, the
    /// same way `should_grease` does -- see `complete_a_read_request`).
    fn consume_probe_token(&self, origin: &ImmutableOrigin) -> bool {
        let mut budgets = self.probe_budgets.lock();
        let now = Instant::now();
        let budget = budgets.entry(origin.clone()).or_insert_with(|| ProbeBudget {
            tokens: PROBE_BUDGET_CAPACITY,
            last_refill: now,
        });

        let elapsed_secs = now.duration_since(budget.last_refill).as_secs_f64();
        budget.tokens =
            (budget.tokens + elapsed_secs * PROBE_BUDGET_REFILL_PER_SECOND).min(PROBE_BUDGET_CAPACITY);
        budget.last_refill = now;

        if budget.tokens >= 1.0 {
            budget.tokens -= 1.0;
            true
        } else {
            false
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
            CosThreadMsg::AbandonPendingWrite(hash) => {
                self.abandon_pending_write(&hash);
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
        // Every read is a probe (see this module's doc comment); an
        // origin over its rate limit is lied to exactly like a real miss,
        // before even looking at the registry, so that a request denied
        // for being over budget is indistinguishable from one that was
        // never present or never disclosed.
        if !self.consume_probe_token(origin) {
            return CosReadOutcome::NotFound;
        }

        // A write lock, not a read lock: a successful list-scoped read
        // mutates the entry's origins list order (`touch_listed_origin`,
        // see this module's doc comment on the LRU merge policy), so
        // this needs mutable access even though it's conceptually "just
        // a read" from the caller's perspective.
        let mut data = self.data.write();
        let Some(entry) = data.entries.get_mut(&registry_key(hash)) else {
            return CosReadOutcome::NotFound;
        };

        if entry.state == CosEntryState::Pending {
            // A stale Pending entry is treated as if it were never
            // created, per this module's doc comment: an abandoned write
            // must not permanently block readers behind PendingWrite.
            return if is_stale_pending(entry) {
                CosReadOutcome::NotFound
            } else {
                CosReadOutcome::PendingWrite
            };
        }

        if !self.apply_availability_gating(entry, hash, origin) {
            return CosReadOutcome::NotFound;
        }

        // Not persisted immediately; see this module's doc comment on
        // why the LRU touch is a soft, in-memory-first mechanism.
        touch_listed_origin(entry, origin);

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
        let key = registry_key(hash);
        // A stale Pending entry from an abandoned write is replaced with
        // a fresh one, same as if the hash had never been requested
        // before; see this module's doc comment. A Written entry, or a
        // Pending one still within the staleness window (an ordinary
        // in-flight write, possibly a genuinely concurrent one from
        // another origin), is left untouched.
        let needs_fresh_entry = match data.entries.get(&key) {
            None => true,
            Some(existing) => is_stale_pending(existing),
        };
        if needs_fresh_entry {
            data.entries.insert(key, CosEntry {
                bytes: None,
                state: CosEntryState::Pending,
                origins: normalized,
                storing_origins: HashSet::new(),
                pending_since_unix_secs: unix_now_secs(),
            });
        }
        self.persist(&data);
    }

    /// See `CosThreadMsg::AbandonPendingWrite`.
    fn abandon_pending_write(&self, hash: &CosHash) {
        let mut data = self.data.write();
        let key = registry_key(hash);
        // Only remove it while still Pending: if another origin's write
        // for the same hash already completed (a genuinely concurrent
        // write racing this now-aborted one), that Written entry must
        // survive this abort.
        if matches!(data.entries.get(&key), Some(entry) if entry.state == CosEntryState::Pending) {
            data.entries.remove(&key);
            self.persist(&data);
        }
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
                pending_since_unix_secs: unix_now_secs(),
            });

        entry.bytes = Some(StoredEntryBytes { bytes, type_string });
        entry.state = CosEntryState::Written;
        entry.storing_origins.insert(origin);
        upgrade_resource_visibility(entry, requested_origins);
        self.persist(&data);

        Ok(())
    }

    /// <https://wicg.github.io/cross-origin-storage/#apply-availability-gating>
    fn apply_availability_gating(
        &self,
        entry: &CosEntry,
        hash: &CosHash,
        origin: &ImmutableOrigin,
    ) -> bool {
        determine_cos_disclosure(entry, hash, origin)
    }
}

/// <https://wicg.github.io/cross-origin-storage/#determine-cos-disclosure>
/// GREASE'ing (see `should_grease`) only ever turns a `Wildcard`-scoped
/// disclosure that would otherwise happen into a lie, never the reverse,
/// and per the spec's own API Response Reference table only applies to
/// requesting origins that are not a storing origin -- which is already
/// guaranteed here, since the early return above already exits before
/// reaching the `Wildcard` arm for a storing origin's own read.
fn determine_cos_disclosure(entry: &CosEntry, hash: &CosHash, origin: &ImmutableOrigin) -> bool {
    if entry.storing_origins.contains(origin) {
        return true;
    }

    match &entry.origins {
        CosOrigins::Wildcard => is_on_public_hash_list(hash) && !should_grease(entry),
        CosOrigins::List(list) => list.contains(origin),
        CosOrigins::SameSiteOnly => entry
            .storing_origins
            .iter()
            .any(|storing_origin| net_traits::pub_domains::is_same_site(origin, storing_origin)),
    }
}

/// <https://wicg.github.io/cross-origin-storage/#phl>: `net_traits::public_hash_list`'s
/// bundled snapshot only lists SHA-256 digests (see that module's doc
/// comment), so a resource hashed with any other algorithm can never be
/// found on it and always fails closed here.
fn is_on_public_hash_list(hash: &CosHash) -> bool {
    hash.algorithm.eq_ignore_ascii_case("SHA-256") &&
        net_traits::public_hash_list::is_hex_digest_on_public_hash_list(&hash.value)
}

/// Probability that an eligible `Wildcard`-scoped, otherwise-disclosed
/// entry is GREASEd (see `should_grease`). Not specified numerically by
/// the spec ("occasionally"); 1% is this implementation's choice.
const GREASE_PROBABILITY: f64 = 0.01;

/// Entries at or above this size are never GREASEd, per this module's
/// doc comment on `should_grease`. 500 KiB is this implementation's
/// choice for where a spurious re-download stops being "inexpensive";
/// the spec gives no numeric threshold, only the qualitative constraint.
const GREASE_MAX_SIZE_BYTES: usize = 500 * 1024;

/// <https://wicg.github.io/cross-origin-storage/#grease>
/// (GREASE: Generate Random Extensions And Sustain Extensibility.) An
/// additional privacy mitigation: occasionally lying and reporting a
/// `Wildcard`-scoped entry as absent even though it is genuinely present
/// and would otherwise be disclosed, so that a false "not found" can
/// never be distinguished from a true one -- callers can't treat a
/// reliable "found" response as proof a resource is actually cached.
///
/// Size-gated per the spec's explicit constraint: "User agents must NOT
/// GREASE responses for files whose size makes a spurious re-download
/// clearly disproportionate to the privacy benefit" -- a false negative
/// on a small file just costs an inexpensive re-fetch, but on a large one
/// (the spec's own example: "gigabyte-scale AI model weights") it would
/// impose a significant, observable bandwidth/latency cost, which would
/// itself leak information (a "found-but-GREASEd" response would be
/// distinguishable from a real miss by its retry latency). Entries with
/// no stored bytes (should not happen for a `Written` entry, but handled
/// rather than assumed) are treated as size `0` and are therefore always
/// eligible -- there is nothing to make an expensive re-download of.
fn should_grease(entry: &CosEntry) -> bool {
    let size = entry.bytes.as_ref().map_or(0, |bytes| bytes.bytes.len());
    size < GREASE_MAX_SIZE_BYTES && rand::random_bool(GREASE_PROBABILITY)
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
                // `candidates` is a single call's own list, already
                // capped at MAX_ORIGINS_LIST_LENGTH by script-side
                // validation (see that constant's doc comment) before
                // this message could even be sent, so no merge/eviction
                // is needed for this (not-yet-list-scoped) case.
                entry.origins = CosOrigins::List(candidates);
            },
            CosOrigins::List(existing) => {
                merge_origins_list(existing, candidates);
            },
            CosOrigins::Wildcard => unreachable!("handled by the early return above"),
        },
    }
}

/// Merges `candidates` into `existing`, per
/// <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>'s
/// merge step. `existing`'s order doubles as an LRU recency signal (see
/// this module's doc comment), so a genuinely new candidate is appended
/// at the back (most-recently-used end) -- a writer actively requesting
/// it right now is itself a legitimate "just used" signal -- while an
/// already-present one is left exactly where it is; re-declaration by a
/// writer is not the same as an actual read, and only `touch_listed_origin`
/// (called from the read path) should refresh recency. If the result
/// would exceed `MAX_ORIGINS_LIST_LENGTH`, the least-recently-used
/// origins (the front of the list) are evicted, silently, until it fits
/// again, per: "Merging origins into an existing list-scoped entry would
/// exceed the implementation-defined maximum length [results in] Success
/// (excess origins silently dropped)".
fn merge_origins_list(existing: &mut Vec<ImmutableOrigin>, candidates: Vec<ImmutableOrigin>) {
    for candidate in candidates {
        if !existing.contains(&candidate) {
            existing.push(candidate);
        }
    }
    while existing.len() > MAX_ORIGINS_LIST_LENGTH {
        existing.remove(0);
    }
}

/// Marks `origin` as just-used within a `CosOrigins::List`-scoped
/// entry's origins list (see this module's doc comment on the LRU merge
/// policy): moves it to the back (most-recently-used end) if present.
/// A no-op if `origin` isn't in the list (e.g. disclosure came from
/// `storing_origins` instead) or `entry` isn't `CosOrigins::List`-scoped.
fn touch_listed_origin(entry: &mut CosEntry, origin: &ImmutableOrigin) {
    if let CosOrigins::List(list) = &mut entry.origins {
        if let Some(position) = list.iter().position(|listed| listed == origin) {
            let touched = list.remove(position);
            list.push(touched);
        }
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
    fn merge_origins_list_appends_new_candidates_at_the_back() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let c = origin("https://c.example.com");
        let mut existing = vec![a.clone(), b.clone()];
        merge_origins_list(&mut existing, vec![c.clone()]);
        assert_eq!(existing, vec![a, b, c]);
    }

    #[test]
    fn merge_origins_list_does_not_move_an_already_present_candidate() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let mut existing = vec![a.clone(), b.clone()];
        // Re-declaring `a` (already present) must not move it: only an
        // actual read should refresh recency, per this module's doc
        // comment.
        merge_origins_list(&mut existing, vec![a.clone()]);
        assert_eq!(existing, vec![a, b]);
    }

    #[test]
    fn merge_origins_list_evicts_the_least_recently_used_when_over_capacity() {
        let mut existing: Vec<ImmutableOrigin> = (0..MAX_ORIGINS_LIST_LENGTH)
            .map(|i| origin(&format!("https://origin{i}.example.com")))
            .collect();
        let new_origin = origin("https://new-collaborator.example.com");
        merge_origins_list(&mut existing, vec![new_origin.clone()]);

        assert_eq!(existing.len(), MAX_ORIGINS_LIST_LENGTH);
        // The origin that was at the front (index 0, least-recently-used)
        // must be the one evicted to make room.
        assert!(!existing.contains(&origin("https://origin0.example.com")));
        // The new one must have been appended at the back.
        assert_eq!(existing.last(), Some(&new_origin));
    }

    #[test]
    fn touch_listed_origin_moves_a_present_origin_to_the_back() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let c = origin("https://c.example.com");
        let mut entry = CosEntry {
            bytes: None,
            state: CosEntryState::Written,
            origins: CosOrigins::List(vec![a.clone(), b.clone(), c.clone()]),
            storing_origins: HashSet::new(),
            pending_since_unix_secs: 0,
        };
        touch_listed_origin(&mut entry, &b);
        assert!(matches!(
            &entry.origins,
            CosOrigins::List(list) if *list == vec![a, c, b]
        ));
    }

    #[test]
    fn touch_listed_origin_is_a_no_op_for_an_absent_origin() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let absent = origin("https://absent.example.com");
        let mut entry = CosEntry {
            bytes: None,
            state: CosEntryState::Written,
            origins: CosOrigins::List(vec![a.clone(), b.clone()]),
            storing_origins: HashSet::new(),
            pending_since_unix_secs: 0,
        };
        touch_listed_origin(&mut entry, &absent);
        assert!(matches!(
            &entry.origins,
            CosOrigins::List(list) if *list == vec![a, b]
        ));
    }

    #[test]
    fn touch_listed_origin_is_a_no_op_for_non_list_scoped_entries() {
        let mut wildcard_entry = CosEntry {
            bytes: None,
            state: CosEntryState::Written,
            origins: CosOrigins::Wildcard,
            storing_origins: HashSet::new(),
            pending_since_unix_secs: 0,
        };
        // Must not panic on a non-`List` entry.
        touch_listed_origin(&mut wildcard_entry, &origin("https://a.example.com"));
        assert!(matches!(wildcard_entry.origins, CosOrigins::Wildcard));
    }

    #[test]
    fn read_touch_updates_lru_order_so_a_recently_read_origin_survives_a_later_merge_eviction() {
        let store = store();
        let writer = origin("https://writer.example.com");
        let listed_origins: Vec<ImmutableOrigin> = (0..MAX_ORIGINS_LIST_LENGTH)
            .map(|i| origin(&format!("https://origin{i}.example.com")))
            .collect();
        let least_recently_used = listed_origins[0].clone();
        let next_least_recently_used = listed_origins[1].clone();
        // A real hash of "tiny", not an arbitrary placeholder: the merge
        // step below goes through the real `verify_and_store`, which
        // recomputes and checks the digest for real, so the content and
        // hash must actually match.
        let content = b"tiny".to_vec();
        let computed = compute_hex_digest("SHA-256", &content).unwrap();
        let h = hash("SHA-256", &computed);
        insert_written_entry_directly(
            &store,
            &h,
            writer,
            CosOrigins::List(listed_origins),
            content.clone(),
        );

        // Reading as the origin currently at the front (least-recently-
        // used) succeeds, and moves it to the back.
        assert!(matches!(
            store.complete_a_read_request(&h, &least_recently_used),
            CosReadOutcome::Found { .. }
        ));

        // Merge in one brand-new origin via a second, independent writer
        // completing a write for the same hash with the same content --
        // exactly the "unrelated origin writes the same byte-identical
        // resource" scenario from this module's doc comment. The list is
        // already at MAX_ORIGINS_LIST_LENGTH, so this must evict exactly
        // one origin to make room.
        let new_origin = origin("https://new-collaborator.example.com");
        let second_writer = origin("https://second-writer.example.com");
        store
            .verify_and_store(
                &h,
                content,
                "text/plain".to_owned(),
                second_writer,
                Some(RequestedOrigins::List(vec![new_origin.clone()])),
            )
            .unwrap();

        // The origin just read from was moved to the back by the read
        // above, so it must survive the eviction...
        assert!(matches!(
            store.complete_a_read_request(&h, &least_recently_used),
            CosReadOutcome::Found { .. }
        ));
        // ...while the origin that was *next* in line (index 1, now at
        // the front after index 0 moved to the back) is the one evicted
        // instead.
        assert!(matches!(
            store.complete_a_read_request(&h, &next_least_recently_used),
            CosReadOutcome::NotFound
        ));
        // And the newly-merged origin is readable.
        assert!(matches!(
            store.complete_a_read_request(&h, &new_origin),
            CosReadOutcome::Found { .. }
        ));
    }

    #[test]
    fn wildcard_entry_is_not_readable_by_an_outside_origin_when_its_hash_is_not_on_the_phl() {
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

        // Fails closed: this hash (of arbitrary test content) is not on
        // the bundled Public Hash List snapshot, so a "*"-scoped entry
        // for it is still not disclosed outside its storing origins.
        assert!(matches!(
            store.complete_a_read_request(&h, &outsider),
            CosReadOutcome::NotFound
        ));
    }

    /// Inserts a `Written` entry directly into `store`'s registry,
    /// bypassing `verify_and_store`'s hash-content matching. Needed for
    /// tests that need a specific, real digest (e.g. one from the bundled
    /// Public Hash List snapshot) rather than whatever `compute_hex_digest`
    /// would produce from arbitrary test bytes.
    fn insert_written_entry_directly(
        store: &CrossOriginStorageStore,
        hash: &CosHash,
        storing_origin: ImmutableOrigin,
        origins: CosOrigins,
        bytes: Vec<u8>,
    ) {
        let mut data = store.data.write();
        data.entries.insert(
            registry_key(hash),
            CosEntry {
                bytes: Some(StoredEntryBytes {
                    bytes,
                    type_string: "text/plain".to_owned(),
                }),
                state: CosEntryState::Written,
                origins,
                storing_origins: HashSet::from([storing_origin]),
                pending_since_unix_secs: 0,
            },
        );
    }

    #[test]
    fn wildcard_entry_is_readable_by_an_outside_origin_when_its_hash_is_on_the_phl() {
        let store = store();
        let writer = origin("https://writer.example");
        let outsider = origin("https://outsider.example");

        // A real digest from the bundled Public Hash List snapshot --
        // the same one `net_traits::public_hash_list`'s own tests use;
        // this may need updating if a future
        // `./mach update-public-hash-list` refresh ever drops it.
        let h = hash(
            "SHA-256",
            "00003bcf96fc9cb1ac3c88678137b49a3a67a7991aa46f8c944fb8756b51b84e",
        );
        // At/above GREASE_MAX_SIZE_BYTES so this test -- which is about
        // PHL disclosure, not GREASE'ing -- is never flaky from a
        // GREASE roll; see the dedicated `should_grease`/GREASE'ing
        // tests below for that.
        insert_written_entry_directly(
            &store,
            &h,
            writer,
            CosOrigins::Wildcard,
            vec![0u8; GREASE_MAX_SIZE_BYTES],
        );

        assert!(matches!(
            store.complete_a_read_request(&h, &outsider),
            CosReadOutcome::Found { .. }
        ));
    }

    #[test]
    fn is_on_public_hash_list_rejects_a_non_sha256_algorithm_even_if_the_value_would_match() {
        // The bundled snapshot is SHA-256 only (see
        // `net_traits::public_hash_list`'s doc comment), so any other
        // algorithm always fails closed regardless of `value`.
        let h = hash(
            "SHA-1",
            "00003bcf96fc9cb1ac3c88678137b49a3a67a7991aa46f8c944fb8756b51b84e",
        );
        assert!(!is_on_public_hash_list(&h));
    }

    #[test]
    fn consume_probe_token_allows_up_to_capacity_then_denies() {
        let store = store();
        let o = origin("https://prober.example");
        let mut allowed = 0;
        for _ in 0..(PROBE_BUDGET_CAPACITY as usize) {
            if store.consume_probe_token(&o) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, PROBE_BUDGET_CAPACITY as usize);
        // One more, immediately: real elapsed time between the loop above
        // and this call is a tiny fraction of a second, negligible next
        // to PROBE_BUDGET_REFILL_PER_SECOND, so no meaningful refill has
        // happened and this must still be denied.
        assert!(!store.consume_probe_token(&o));
    }

    #[test]
    fn consume_probe_token_tracks_budget_independently_per_origin() {
        let store = store();
        let a = origin("https://a.example");
        let b = origin("https://b.example");
        for _ in 0..(PROBE_BUDGET_CAPACITY as usize) {
            assert!(store.consume_probe_token(&a));
        }
        assert!(!store.consume_probe_token(&a));
        // b's budget is untouched by a's exhaustion.
        assert!(store.consume_probe_token(&b));
    }

    #[test]
    fn consume_probe_token_refills_over_time() {
        let store = store();
        let o = origin("https://prober.example");
        for _ in 0..(PROBE_BUDGET_CAPACITY as usize) {
            assert!(store.consume_probe_token(&o));
        }
        assert!(!store.consume_probe_token(&o));

        std::thread::sleep(std::time::Duration::from_millis(200));
        // At PROBE_BUDGET_REFILL_PER_SECOND tokens/sec, 200ms refills
        // ~4 tokens -- comfortably at least 1, so this must now succeed.
        assert!(store.consume_probe_token(&o));
    }

    #[test]
    fn read_probe_budget_exhaustion_returns_not_found_even_though_entry_exists() {
        let store = store();
        let writer = origin("https://writer.example.com");
        let prober = origin("https://prober.example.com");
        let h = hash("SHA-256", &"d".repeat(64));
        // List-scoped so `prober` is explicitly allowed to read it --
        // isolates this test to budget exhaustion, not availability
        // gating.
        insert_written_entry_directly(
            &store,
            &h,
            writer,
            CosOrigins::List(vec![prober.clone()]),
            b"tiny".to_vec(),
        );

        let mut found_count = 0;
        let mut not_found_count = 0;
        for _ in 0..(PROBE_BUDGET_CAPACITY as usize + 5) {
            match store.complete_a_read_request(&h, &prober) {
                CosReadOutcome::Found { .. } => found_count += 1,
                CosReadOutcome::NotFound => not_found_count += 1,
                CosReadOutcome::PendingWrite => panic!("unexpected PendingWrite"),
            }
        }
        assert_eq!(found_count, PROBE_BUDGET_CAPACITY as usize);
        assert_eq!(not_found_count, 5);
    }

    #[test]
    fn probe_budget_is_shared_across_different_hashes_for_the_same_origin() {
        let store = store();
        let writer = origin("https://writer.example.com");
        let prober = origin("https://prober.example.com");
        let h1 = hash("SHA-256", &"e".repeat(64));
        let h2 = hash("SHA-256", &"f".repeat(64));
        insert_written_entry_directly(
            &store,
            &h1,
            writer.clone(),
            CosOrigins::List(vec![prober.clone()]),
            b"tiny".to_vec(),
        );
        insert_written_entry_directly(
            &store,
            &h2,
            writer,
            CosOrigins::List(vec![prober.clone()]),
            b"tiny".to_vec(),
        );

        // Drain the budget entirely via h1...
        for _ in 0..(PROBE_BUDGET_CAPACITY as usize) {
            store.complete_a_read_request(&h1, &prober);
        }
        // ...and confirm h2 is now also budget-exhausted for the same
        // origin, since the budget is per-origin, not per-hash.
        assert!(matches!(
            store.complete_a_read_request(&h2, &prober),
            CosReadOutcome::NotFound
        ));
    }

    #[test]
    fn should_grease_never_greases_entries_at_or_above_the_size_cap() {
        let entry = CosEntry {
            bytes: Some(StoredEntryBytes {
                bytes: vec![0u8; GREASE_MAX_SIZE_BYTES],
                type_string: "application/octet-stream".to_owned(),
            }),
            state: CosEntryState::Written,
            origins: CosOrigins::Wildcard,
            storing_origins: HashSet::new(),
            pending_since_unix_secs: 0,
        };
        for _ in 0..500 {
            assert!(!should_grease(&entry));
        }
    }

    #[test]
    fn should_grease_sometimes_greases_entries_under_the_size_cap() {
        let entry = CosEntry {
            bytes: Some(StoredEntryBytes {
                bytes: vec![0u8; 10],
                type_string: "text/plain".to_owned(),
            }),
            state: CosEntryState::Written,
            origins: CosOrigins::Wildcard,
            storing_origins: HashSet::new(),
            pending_since_unix_secs: 0,
        };
        let trials = 3000;
        let greased_count = (0..trials).filter(|_| should_grease(&entry)).count();
        // With p=0.1 and 3000 trials, both "always false" and "always
        // true" are astronomically unlikely (binomial tail probability
        // effectively zero); a wide pass band avoids ever flaking in
        // practice while still proving randomness is actually wired up.
        assert!(
            greased_count > 0,
            "expected at least one GREASEd result out of {trials} trials"
        );
        assert!(
            greased_count < trials,
            "expected at least one non-GREASEd result out of {trials} trials"
        );
    }

    #[test]
    fn wildcard_small_on_phl_entry_is_sometimes_greased_for_an_outside_origin() {
        let store = store();
        let writer = origin("https://writer.example");
        let outsider = origin("https://outsider.example");
        let h = hash(
            "SHA-256",
            "00003bcf96fc9cb1ac3c88678137b49a3a67a7991aa46f8c944fb8756b51b84e",
        );
        insert_written_entry_directly(&store, &h, writer, CosOrigins::Wildcard, b"tiny".to_vec());

        // Fewer trials than PROBE_BUDGET_CAPACITY, deliberately: this
        // test is about GREASE'ing specifically, and every trial here
        // reuses the same requesting origin's read-probe budget (see
        // `consume_probe_token`), so a trial count at or above that
        // budget would start returning NotFound from budget exhaustion
        // too, confounding what this test is meant to isolate. At p=1%
        // and 1500 trials, both outcomes are still all but certain
        // (binomial tail probability of all-same-outcome is effectively
        // zero).
        let trials = 1500;
        let mut found = 0;
        let mut not_found = 0;
        for _ in 0..trials {
            match store.complete_a_read_request(&h, &outsider) {
                CosReadOutcome::Found { .. } => found += 1,
                CosReadOutcome::NotFound => not_found += 1,
                CosReadOutcome::PendingWrite => panic!("unexpected PendingWrite"),
            }
        }
        assert!(found > 0, "expected at least one Found (not always GREASEd)");
        assert!(
            not_found > 0,
            "expected at least one NotFound (GREASEd at least once) out of {trials} trials"
        );
    }

    #[test]
    fn wildcard_large_on_phl_entry_is_never_greased_for_an_outside_origin() {
        let store = store();
        let writer = origin("https://writer.example");
        let outsider = origin("https://outsider.example");
        let h = hash(
            "SHA-256",
            "00003bcf96fc9cb1ac3c88678137b49a3a67a7991aa46f8c944fb8756b51b84e",
        );
        insert_written_entry_directly(
            &store,
            &h,
            writer,
            CosOrigins::Wildcard,
            vec![0u8; GREASE_MAX_SIZE_BYTES],
        );

        for _ in 0..500 {
            assert!(matches!(
                store.complete_a_read_request(&h, &outsider),
                CosReadOutcome::Found { .. }
            ));
        }
    }

    #[test]
    fn list_scoped_small_entry_is_never_greased_for_a_listed_origin() {
        // GREASE'ing applies only to Wildcard-scoped entries; List-scoped
        // ones must never be GREASEd regardless of size.
        let store = store();
        let writer = origin("https://writer.example.com");
        let listed = origin("https://listed.example.com");
        let h = hash("SHA-256", &"b".repeat(64));
        insert_written_entry_directly(
            &store,
            &h,
            writer,
            CosOrigins::List(vec![listed.clone()]),
            b"tiny".to_vec(),
        );

        for _ in 0..500 {
            assert!(matches!(
                store.complete_a_read_request(&h, &listed),
                CosReadOutcome::Found { .. }
            ));
        }
    }

    #[test]
    fn same_site_only_small_entry_is_never_greased_for_a_same_site_origin() {
        // GREASE'ing applies only to Wildcard-scoped entries; SameSiteOnly
        // ones must never be GREASEd regardless of size.
        let store = store();
        let writer = origin("https://writer.example.com");
        let same_site_reader = origin("https://reader.example.com");
        let h = hash("SHA-256", &"c".repeat(64));
        insert_written_entry_directly(
            &store,
            &h,
            writer,
            CosOrigins::SameSiteOnly,
            b"tiny".to_vec(),
        );

        for _ in 0..500 {
            assert!(matches!(
                store.complete_a_read_request(&h, &same_site_reader),
                CosReadOutcome::Found { .. }
            ));
        }
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
    fn fresh_pending_entry_blocks_readers_with_pending_write() {
        let store = store();
        let h = hash("SHA-256", &"1".repeat(64));
        let reader = origin("https://reader.example");

        store.complete_a_create_request(&h, None);

        assert!(matches!(
            store.complete_a_read_request(&h, &reader),
            CosReadOutcome::PendingWrite
        ));
    }

    #[test]
    fn stale_pending_entry_reads_as_not_found_instead_of_pending_write() {
        let store = store();
        let h = hash("SHA-256", &"2".repeat(64));
        let reader = origin("https://reader.example");

        store.complete_a_create_request(&h, None);
        backdate_pending_entry(&store, &h);

        assert!(matches!(
            store.complete_a_read_request(&h, &reader),
            CosReadOutcome::NotFound
        ));
    }

    #[test]
    fn stale_pending_entry_is_replaced_by_a_fresh_create_request_and_becomes_writable() {
        let store = store();
        let h = hash("SHA-256", &"3".repeat(64));
        let writer = origin("https://writer.example");

        // First attempt: created, then abandoned (backdated to simulate
        // a page that navigated away without ever closing or aborting).
        store.complete_a_create_request(&h, None);
        backdate_pending_entry(&store, &h);

        // A second create request for the same hash must not stay stuck
        // behind the stale entry -- it gets a fresh one, and a real write
        // against it succeeds normally.
        store.complete_a_create_request(&h, None);
        let bytes = b"retried after abandonment".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        store.complete_a_create_request(&h, None);
        store
            .verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None)
            .unwrap();

        match store.complete_a_read_request(&h, &writer) {
            CosReadOutcome::Found { bytes: found, .. } => assert_eq!(found, bytes),
            other => panic!("expected the retried write to succeed, got {other:?}"),
        }
    }

    #[test]
    fn abandon_pending_write_removes_a_still_pending_entry_immediately() {
        let store = store();
        let h = hash("SHA-256", &"4".repeat(64));
        let reader = origin("https://reader.example");

        store.complete_a_create_request(&h, None);
        store.abandon_pending_write(&h);

        // Gone entirely, not just stale -- a fresh create request should
        // insert a brand new entry rather than finding anything to leave
        // alone or replace.
        assert!(matches!(
            store.complete_a_read_request(&h, &reader),
            CosReadOutcome::NotFound
        ));
        assert!(!store.data.read().entries.contains_key(&registry_key(&h)));
    }

    #[test]
    fn abandon_pending_write_does_not_remove_an_already_written_entry() {
        // A benign race: origin A's write is aborted after origin B's
        // write for the same hash already completed. The completed entry
        // must survive A's (now-late) abandonment signal.
        let store = store();
        let bytes = b"already-written-by-someone-else".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");

        store
            .verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None)
            .unwrap();
        store.abandon_pending_write(&h);

        match store.complete_a_read_request(&h, &writer) {
            CosReadOutcome::Found { bytes: found, .. } => assert_eq!(found, bytes),
            other => panic!("expected the written entry to survive, got {other:?}"),
        }
    }

    /// Rewrites `hash`'s entry (which must already exist and be Pending)
    /// to look like it was created long enough ago to count as
    /// abandoned, without waiting `PENDING_ENTRY_STALE_AFTER_SECS` for
    /// real.
    fn backdate_pending_entry(store: &CrossOriginStorageStore, hash: &CosHash) {
        let mut data = store.data.write();
        let entry = data.entries.get_mut(&registry_key(hash)).unwrap();
        assert_eq!(entry.state, CosEntryState::Pending);
        entry.pending_since_unix_secs = 0;
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
