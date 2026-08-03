/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The Cross-Origin Storage registry
//! (<https://wicg.github.io/cross-origin-storage/#cos-entries>): shared
//! across every script thread that talks to this resource thread (via
//! `Arc<RwLock<...>>`, following `FileManager`'s shape in
//! `filemanager_thread.rs`), and persisted to disk under `config_dir`,
//! one small file per entry, using the same `servo_base::write_json_to_file`
//! helper already used for the cookie jar, HSTS list, and auth cache in
//! `resource_thread.rs`.
//!
//! `script::dom::crossoriginstorage::registry` is a thin IPC client for
//! this service, not the source of truth; the actual spec algorithms
//! (entry state machine, origins scoping, storing-origins bookkeeping,
//! availability gating, visibility-upgrade merging, hash verification)
//! live here.
//!
//! Explicitly NOT real:
//! - Persistence of any one entry is not transactional; two resource
//!   threads racing to write the *same* entry's file (which should not
//!   normally happen -- there is one resource thread per Servo instance)
//!   would not be safe, but that is not a realistic configuration here.
//!   Different entries' files are fully independent, so this does not
//!   extend to ordinary concurrent activity across different hashes.
//!
//! `Wildcard`-scoped (`origins: '*'`) disclosure uses the real Public
//! Hash List (PHL): `net_traits::public_hash_list::is_hex_digest_on_public_hash_list`,
//! a bundled, sorted-for-binary-search snapshot of
//! <https://github.com/tomayac/public-hash-list> (refreshed by
//! `./mach update-public-hash-list`, also run weekly in CI -- see that
//! module's doc comment). A hash not on the list fails closed: only a
//! `Wildcard`-scoped entry whose hash is confirmed present on the PHL is
//! disclosed to non-storing origins; every other `Wildcard`-scoped entry
//! stays hidden from them.
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
//! has no return value at all (see its own doc comment), so it is not a
//! *fingerprinting* oracle the way reads are -- but it still shares
//! `verify_and_store`'s `consume_write_token` write-probe budget (see
//! `WRITE_BUDGET_CAPACITY`'s doc comment for why writes get a smaller,
//! slower budget than reads), since a `create()` is the first step of a
//! write attempt and unbounded `create()` calls are still real registry
//! churn and disk I/O (each one that needs a fresh entry persists its own
//! entry file) worth bounding, independent of whether they are ever
//! observable to the calling script.
//!
//! `verify_and_store` also enforces a storage budget, not spec-mandated
//! (the explainer only mentions LRU-based eviction under storage
//! pressure as one *possible* approach, with no numeric guidance): a
//! global cap (`storage_budget`, a stable fraction of **total** disk
//! capacity -- see `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc comment for
//! why total capacity rather than available free space, matching real
//! browser precedent) and a per-origin share of that cap
//! (`per_origin_share`, `PER_ORIGIN_STORAGE_SHARE_FRACTION`). The two
//! exist for different reasons: the global cap bounds how much disk
//! Cross-Origin Storage can ever consume; the per-origin share exists so
//! that a single origin writing a lot can never force eviction of a
//! *different* origin's data merely by being more recent -- once an
//! origin is at its own share, further writes only ever evict that same
//! origin's own sole-owned entries (`evict_sole_owned_entries_for_origin`),
//! never a shared or other-owned one. Only when several *different*
//! origins, each within their own share, collectively exceed the global
//! cap does eviction fall back to plain cross-origin least-recently-used
//! (`evict_globally_lru`) -- fair there, since it reflects genuine
//! multi-tenant demand, not one origin crowding out another. A write that
//! still doesn't fit even after every eviction it's entitled to rejects
//! with `QuotaExceededError` rather than exceeding the budget.
//!
//! Separately, `verify_and_store` also checks real, currently *available*
//! disk space as an internal-only safety net (never reported -- see
//! `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc comment), since the total-
//! disk-based nominal budget above can nominally "allow" a write that
//! genuinely would not fit right now.
//!
//! `SameSiteOnly` disclosure uses `net_traits::pub_domains::is_same_site`
//! (Public Suffix List-backed eTLD+1 comparison, the same helper the
//! cookie jar uses for `SameSite`): `https://a.example.com` and
//! `https://b.example.com` are same-site (same registrable domain,
//! different origins), while `https://example.com` and
//! `https://example.co.uk` are not, despite superficially similar names.
//!
//! Every entry lives under `config_dir/cos_entries/` as a pair of sibling
//! files, both named after `registry_key()`'s sanitized form: `<key>.json`
//! (metadata -- state, origins, storing-origins, timestamps; written by
//! `persist_entry()`) and `<key>.bin` (raw bytes, written by
//! `persist_entry_bytes()`, only for a `Written` entry). Keeping bytes out
//! of the metadata file means a mutation that only touches metadata (e.g.
//! a fresh `Pending` entry from `complete_a_create_request`) never has to
//! rewrite any entry's bytes, and vice versa. Metadata is itself split
//! one file per entry, so `persist_entry()`'s cost is proportional to the
//! size of the one entry that actually changed, not the number of
//! entries in the registry -- writing or reading back one entry never
//! implies touching any other one. `CrossOriginStorageStore::new()`
//! loads the registry by scanning this directory for `.json` files.
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
//! The touch is persisted immediately (`complete_a_read_request` calls
//! `persist_entry()` after it, alongside the `last_read_unix_secs` update
//! below), which is affordable now that a mutation's persistence cost is
//! proportional to the one entry touched, not the whole registry (see
//! this module's doc comment on per-entry persistence).
//!
//! `CosEntry::last_read_unix_secs` is a *separate* recency signal from
//! the origins-list order above: it tracks how recently an *entry*
//! (rather than an origin within one entry's list) was last read, and
//! drives storage-budget eviction order (`evict_sole_owned_entries_for_origin`,
//! `evict_globally_lru`) instead of the origins-list length cap. It is a
//! plain wall-clock timestamp (`#[serde(default)]` for forward
//! compatibility with a registry saved before this field existed), set
//! and persisted by `complete_a_read_request` on every genuine `Found`
//! read, so eviction order survives a restart accurately instead of
//! reflecting whenever the entry was last *written*. It is still only
//! updated on a genuine `Found` read, not a write: an entry being merely
//! re-verified by a writer is not the same as being read by some other
//! origin.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use log::warn;
use net_traits::cross_origin_storage_thread::{
    CosHash, CosReadOutcome, CosThreadMsg, MAX_ORIGINS_LIST_LENGTH, RequestedOrigins,
    VerifyAndStoreOutcome,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use servo_url::ImmutableOrigin;

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

/// `key` (`registry_key()`'s `"ALGORITHM:hex_value"` form) with `:`
/// replaced, since it is not a safe filename character on every platform
/// this needs to run on. Shared basename for both an entry's bytes file
/// and its metadata file; see `entry_bytes_path`/`entry_metadata_path`.
fn sanitized_entry_key(key: &str) -> String {
    key.replace(':', "_")
}

/// Path of the on-disk file holding one entry's raw bytes; see this
/// module's doc comment on per-entry persistence.
fn entry_bytes_path(config_dir: &Path, key: &str) -> PathBuf {
    config_dir
        .join(ENTRY_BYTES_DIR)
        .join(format!("{}.bin", sanitized_entry_key(key)))
}

/// Path of the on-disk file holding one entry's metadata (a
/// `PersistedEntry`); see this module's doc comment on per-entry
/// persistence.
fn entry_metadata_path(config_dir: &Path, key: &str) -> PathBuf {
    config_dir
        .join(ENTRY_BYTES_DIR)
        .join(format!("{}.json", sanitized_entry_key(key)))
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
    /// Not part of the entry's metadata JSON; see this module's doc
    /// comment. Populated from its own per-entry file, either right after a
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
    /// Seconds since the Unix epoch when this entry was last successfully
    /// read (a `Found` outcome), or written if never read since. Drives
    /// storage-budget eviction order (oldest first); see this module's
    /// doc comment on storage budgeting. `#[serde(default)]` so a
    /// registry persisted before this field existed still deserializes,
    /// with old entries defaulting to the oldest possible value (`0`) --
    /// making them the first ones evicted, a reasonable default for
    /// entries this implementation has no real recency information about
    /// yet.
    #[serde(default)]
    last_read_unix_secs: u64,
}

/// Whether `entry` is a `Pending` entry old enough to be treated as
/// abandoned; see this module's doc comment.
fn is_stale_pending(entry: &CosEntry) -> bool {
    entry.state == CosEntryState::Pending &&
        unix_now_secs().saturating_sub(entry.pending_since_unix_secs) > PENDING_ENTRY_STALE_AFTER_SECS
}

/// The in-memory registry contents. `HashMap` keys here are plain
/// `String`s (`registry_key()`'s normalized `"ALGORITHM:value"` form):
/// `serde_json` cannot serialize a tuple as a JSON object key, only a
/// plain string. Never serialized as a whole; see this module's doc
/// comment on per-entry persistence -- `PersistedEntry` is the unit that
/// actually round-trips through JSON.
#[derive(Default)]
struct CosRegistryData {
    entries: HashMap<String, CosEntry>,
}

/// On-disk shape of one entry's metadata file (`entry_metadata_path()`),
/// for reading it back. Bundles the registry key alongside the entry
/// itself, since a standalone file has no field name of its own to double
/// as a key the way a JSON object's entries do -- `CrossOriginStorageStore::new()`
/// needs the key back explicitly to reconstruct the in-memory `HashMap`
/// when scanning `cos_entries/` on startup. See `PersistedEntryRef` for
/// the write side.
#[derive(Deserialize)]
struct PersistedEntry {
    key: String,
    entry: CosEntry,
}

/// Reference-only counterpart of `PersistedEntry`, used by
/// `persist_entry()` to write an entry's metadata without cloning its
/// (potentially large, e.g. multi-hundred-MiB AI model weights)
/// in-memory bytes first -- `StoredEntryBytes::bytes` is `#[serde(skip)]`
/// regardless, but a `CosEntry::clone()` would still physically copy
/// that `Vec<u8>` before serialization ever got the chance to skip it.
#[derive(Serialize)]
struct PersistedEntryRef<'a> {
    key: &'a str,
    entry: &'a CosEntry,
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

/// Burst capacity and steady-state refill rate for this implementation's
/// per-origin *write*-probe rate limit (`consume_write_token`), the
/// same mechanism as the read-probe budget above but shared by both
/// `complete_a_create_request` and `verify_and_store`: an origin
/// flooding `create()`/`close()` calls churns the registry and disk I/O
/// regardless of whether writes are ever actually observable the way
/// reads are (see this module's doc comment). One shared budget rather
/// than two separate ones, since `create()` is just the first step of a
/// write attempt -- spending it on `create()` calls correspondingly
/// reduces what is left for the `verify_and_store` that would normally
/// follow. Smaller and slower than the read budget, since a write is
/// inherently more expensive for a caller to mount than a read (it has
/// to actually transmit and hash real bytes), and a legitimate cold
/// cache load still means writing each missing shard only *once*, not
/// repeatedly.
const WRITE_BUDGET_CAPACITY: f64 = 200.0;
const WRITE_BUDGET_REFILL_PER_SECOND: f64 = 2.0;

/// One requesting origin's rate-limit state for either the read-probe or
/// write-probe budget (each origin gets one bucket per budget kind); see
/// `consume_token`.
struct TokenBucket {
    /// Current token balance. `f64`, not an integer count, since refill
    /// accrues continuously (a fraction of a token per elapsed
    /// millisecond) rather than in discrete per-second ticks -- this
    /// avoids the token bucket needing its own timer/task, since it can
    /// just compute elapsed time lazily on each probe instead.
    tokens: f64,
    last_refill: Instant,
}

/// Consumes one token from `origin`'s bucket in `buckets` (creating it
/// at full `capacity` if this is the first time `origin` has been seen),
/// refilling first based on elapsed time at `refill_per_second`. Shared
/// by `consume_probe_token` and `consume_write_token`, which just supply
/// different maps/constants; see those methods' doc comments for what
/// each is for.
fn consume_token(
    buckets: &Mutex<HashMap<ImmutableOrigin, TokenBucket>>,
    origin: &ImmutableOrigin,
    capacity: f64,
    refill_per_second: f64,
) -> bool {
    let mut buckets = buckets.lock();
    let now = Instant::now();
    let bucket = buckets.entry(origin.clone()).or_insert_with(|| TokenBucket {
        tokens: capacity,
        last_refill: now,
    });

    let elapsed_secs = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed_secs * refill_per_second).min(capacity);
    bucket.last_refill = now;

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
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
    probe_budgets: Arc<Mutex<HashMap<ImmutableOrigin, TokenBucket>>>,
    /// Write-probe rate-limit state per requesting origin; see
    /// `consume_write_token`. Same not-persisted reasoning as
    /// `probe_budgets` above.
    write_budgets: Arc<Mutex<HashMap<ImmutableOrigin, TokenBucket>>>,
    /// Test-only override for `query_free_disk_space` (the internal,
    /// never-reported safety-net check -- see
    /// `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc comment). `None` in
    /// production.
    #[cfg(test)]
    fake_free_disk_space: Option<u64>,
    /// Test-only override for `query_total_disk_space` (the basis for
    /// the *nominal* storage budget): lets storage-budget tests exercise
    /// real eviction/rejection behavior through the actual
    /// `verify_and_store` path with a small, controlled budget, instead
    /// of the real disk's total capacity (which, for any realistic test
    /// payload, is effectively unlimited and would never naturally
    /// trigger eviction). `None` in production.
    #[cfg(test)]
    fake_total_disk_space: Option<u64>,
}

impl CrossOriginStorageStore {
    pub fn new(config_dir: Option<PathBuf>) -> Self {
        let mut entries = HashMap::new();
        if let Some(dir) = &config_dir {
            entries = Self::load_entries_from_disk(dir);
        }
        let data = CosRegistryData { entries };
        CrossOriginStorageStore {
            data: Arc::new(RwLock::new(data)),
            config_dir,
            probe_budgets: Arc::new(Mutex::new(HashMap::new())),
            write_budgets: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            fake_free_disk_space: None,
            #[cfg(test)]
            fake_total_disk_space: None,
        }
    }

    /// Loads the registry back by scanning `dir/cos_entries/` for `.json`
    /// metadata files (see this module's doc comment on per-entry
    /// persistence), rather than reading one combined file. A file that
    /// can't be read or decoded is skipped with a warning -- one corrupt
    /// entry must not prevent every other entry from loading.
    fn load_entries_from_disk(dir: &Path) -> HashMap<String, CosEntry> {
        let mut entries = HashMap::new();
        let read_dir = match std::fs::read_dir(dir.join(ENTRY_BYTES_DIR)) {
            Ok(read_dir) => read_dir,
            // No entries have ever been persisted yet -- an empty
            // registry, not a warning-worthy problem.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return entries,
            Err(err) => {
                warn!("Could not read {}: {err}", dir.join(ENTRY_BYTES_DIR).display());
                return entries;
            },
        };
        for dir_entry in read_dir.flatten() {
            let path = dir_entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let contents = match std::fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(err) => {
                    warn!("Could not read Cross-Origin Storage entry metadata at {}: {err}", path.display());
                    continue;
                },
            };
            let persisted: PersistedEntry = match serde_json::from_str(&contents) {
                Ok(persisted) => persisted,
                Err(err) => {
                    warn!("Could not decode Cross-Origin Storage entry metadata at {}: {err}", path.display());
                    continue;
                },
            };
            let PersistedEntry { key, mut entry } = persisted;
            // The metadata file only records *that* a written entry has
            // bytes (via `Some(StoredEntryBytes)`), not the bytes
            // themselves -- load each one back from its own sibling file
            // now.
            if entry.bytes.is_some() {
                match std::fs::read(entry_bytes_path(dir, &key)) {
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
            entries.insert(key, entry);
        }
        entries
    }

    /// <https://wicg.github.io/cross-origin-storage/#read-requests> notes
    /// user agents "are expected to implement safeguards against such
    /// attacks, for example, by limiting the number of probes"; this is
    /// that safeguard: `PROBE_BUDGET_CAPACITY` tokens available in a
    /// burst per requesting origin, refilling at
    /// `PROBE_BUDGET_REFILL_PER_SECOND` tokens/second thereafter (see
    /// `consume_token`). Returns whether a token was available (the
    /// probe may proceed) or the origin is over budget (the caller
    /// should lie, the same way `should_grease` does -- see
    /// `complete_a_read_request`).
    fn consume_probe_token(&self, origin: &ImmutableOrigin) -> bool {
        consume_token(
            &self.probe_budgets,
            origin,
            PROBE_BUDGET_CAPACITY,
            PROBE_BUDGET_REFILL_PER_SECOND,
        )
    }

    /// The write counterpart of `consume_probe_token`, shared by
    /// `complete_a_create_request` and `verify_and_store`; see
    /// `WRITE_BUDGET_CAPACITY`'s doc comment for why it has different
    /// numbers and why one budget covers both callers. Returns whether a
    /// token was available (the caller may proceed) or the origin is
    /// over budget. The two callers respond differently when out of
    /// budget: `verify_and_store` rejects with a real, distinguishable
    /// error (unlike a read, a write has no honest way to "lie" about
    /// having happened -- silently pretending success without actually
    /// storing the caller's data would be a correctness problem, not
    /// just a privacy one), while `complete_a_create_request` -- which
    /// has no return value to reject with in the first place -- simply
    /// no-ops.
    fn consume_write_token(&self, origin: &ImmutableOrigin) -> bool {
        consume_token(
            &self.write_budgets,
            origin,
            WRITE_BUDGET_CAPACITY,
            WRITE_BUDGET_REFILL_PER_SECOND,
        )
    }

    /// Real, currently-available free space on the filesystem backing
    /// `config_dir` -- used only as `verify_and_store`'s internal,
    /// never-reported safety net; see `GLOBAL_STORAGE_BUDGET_FRACTION`'s
    /// doc comment for why the *nominal* budget uses
    /// `query_total_disk_space` instead. `config_dir: None` (no real
    /// persistence at all; see `new()`'s doc comment -- only in tests)
    /// is treated as effectively unbounded rather than querying a
    /// nonsensical path, so this safety net never spuriously kicks in
    /// for tests that don't care about it.
    fn query_free_disk_space(&self) -> u64 {
        #[cfg(test)]
        if let Some(fake) = self.fake_free_disk_space {
            return fake;
        }
        let Some(dir) = &self.config_dir else {
            return u64::MAX / 2;
        };
        free_disk_space_at(dir)
    }

    /// Test-only: overrides `query_free_disk_space`'s result; see
    /// `fake_free_disk_space`'s doc comment.
    #[cfg(test)]
    fn set_fake_free_disk_space(&mut self, bytes: u64) {
        self.fake_free_disk_space = Some(bytes);
    }

    /// Total capacity of the filesystem backing `config_dir`, for
    /// `storage_budget`. `config_dir: None` is treated the same
    /// unbounded way as `query_free_disk_space`, for the same reason.
    fn query_total_disk_space(&self) -> u64 {
        #[cfg(test)]
        if let Some(fake) = self.fake_total_disk_space {
            return fake;
        }
        let Some(dir) = &self.config_dir else {
            return u64::MAX / 2;
        };
        total_disk_space_at(dir)
    }

    /// Test-only: overrides `query_total_disk_space`'s result; see
    /// `fake_total_disk_space`'s doc comment.
    #[cfg(test)]
    fn set_fake_total_disk_space(&mut self, bytes: u64) {
        self.fake_total_disk_space = Some(bytes);
    }

    /// Persists one entry's metadata (state, origins, storing-origins,
    /// timestamps) to its own file -- deliberately not entry bytes, which
    /// go through `persist_entry_bytes` instead; see this module's doc
    /// comment on per-entry persistence.
    fn persist_entry(&self, key: &str, entry: &CosEntry) {
        let Some(dir) = &self.config_dir else {
            return;
        };
        let entries_dir = dir.join(ENTRY_BYTES_DIR);
        if let Err(err) = std::fs::create_dir_all(&entries_dir) {
            warn!("Could not create {}: {err}", entries_dir.display());
            return;
        }
        let persisted = PersistedEntryRef { key, entry };
        let filename = format!("{}.json", sanitized_entry_key(key));
        servo_base::write_json_to_file(&persisted, &entries_dir, &filename);
    }

    /// Persists one entry's raw bytes to its own file, alongside (not
    /// combined with) its metadata; see `persist_entry` and this module's
    /// doc comment on per-entry persistence.
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
            CosThreadMsg::Create(hash, origin, requested_origins) => {
                self.complete_a_create_request(&hash, &origin, requested_origins);
            },
            CosThreadMsg::AbandonPendingWrite(hash) => {
                self.abandon_pending_write(&hash);
            },
            CosThreadMsg::VerifyAndStore(hash, bytes, type_string, origin, requested_origins, response_sender) => {
                let outcome =
                    self.verify_and_store(&hash, bytes, type_string, origin, requested_origins);
                let _ = response_sender.send(outcome);
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
        let key = registry_key(hash);
        let Some(entry) = data.entries.get_mut(&key) else {
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

        touch_listed_origin(entry, origin);
        if entry.bytes.is_some() {
            // Drives storage-budget eviction order; see this module's
            // doc comment on storage budgeting. Set before the match
            // below (rather than inside its `Some` arm) so this mutable
            // access to `entry` doesn't overlap with `entry.bytes`'s
            // shared borrow there.
            entry.last_read_unix_secs = unix_now_secs();
            // Persisted immediately, alongside the origins-list touch
            // above: see this module's doc comment on per-entry
            // persistence and on `last_read_unix_secs` for why this is
            // now affordable and necessary for eviction order to survive
            // a restart accurately.
            self.persist_entry(&key, entry);
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
    /// Shares `verify_and_store`'s write-probe budget
    /// (`consume_write_token`): a `create()` call is the first step of a
    /// write attempt, and gating it separately would just add a second
    /// budget to reason about for no real benefit -- an origin that
    /// spends its budget on `create()` calls has correspondingly less
    /// left for the `verify_and_store` that would normally follow, so
    /// the abuse is still bounded either way. Rate-limited here means a
    /// silent no-op, matching this function's existing "no response
    /// expected" shape (see its caller's doc comment): script still gets
    /// a handle back regardless (`crossoriginstoragemanager.rs` never
    /// awaited this call anyway), and if the abuse continues into an
    /// actual `close()`, that surfaces the real, visible
    /// `NotAllowedError` via `verify_and_store`'s own `RateLimited`.
    fn complete_a_create_request(
        &self,
        hash: &CosHash,
        origin: &ImmutableOrigin,
        requested_origins: Option<RequestedOrigins>,
    ) {
        if !self.consume_write_token(origin) {
            return;
        }

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
            let entry = CosEntry {
                bytes: None,
                state: CosEntryState::Pending,
                origins: normalized,
                storing_origins: HashSet::new(),
                pending_since_unix_secs: unix_now_secs(),
                last_read_unix_secs: unix_now_secs(),
            };
            // Only persisted when something actually changed: unlike
            // `verify_and_store`, a repeated `create()` call for a hash
            // that already has a fresh entry is a legitimate, common,
            // idempotent no-op (the same handle-obtaining call a page
            // might make many times for the same hash), and writing an
            // entry file for it every time would be a real, needless
            // disk-I/O cost with no corresponding state change to
            // justify it.
            self.persist_entry(&key, &entry);
            data.entries.insert(key, entry);
        }
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
            delete_entry_metadata_file(self.config_dir.as_deref(), &key);
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
    ) -> VerifyAndStoreOutcome {
        if !self.consume_write_token(&origin) {
            return VerifyAndStoreOutcome::RateLimited;
        }

        let Some(computed_hex) = compute_hex_digest(&hash.algorithm, &bytes) else {
            return VerifyAndStoreOutcome::HashMismatch;
        };
        if computed_hex != hash.value.to_ascii_lowercase() {
            return VerifyAndStoreOutcome::HashMismatch;
        }

        let key = registry_key(hash);
        let new_bytes_len = bytes.len() as u64;

        // Held for the whole operation below (quota check, eviction, and
        // the disk write itself), unlike a plain metadata mutation
        // elsewhere in this file: an eviction decision has to be made
        // against the same in-memory state it then acts on, and this
        // module's doc comment already documents that persistence here
        // is not safe across multiple concurrent resource threads anyway
        // (not a realistic configuration for this implementation).
        let mut data = self.data.write();

        let already_storing = data
            .entries
            .get(&key)
            .is_some_and(|entry| entry.storing_origins.contains(&origin));

        let budget = storage_budget(self.query_total_disk_space());

        // A hash's content can never change (it is, definitionally, the
        // hash of that content), so an origin re-verifying a hash it
        // already stores can never grow its own usage -- only a
        // genuinely new (to this origin) entry needs a quota check.
        if !already_storing {
            let share = per_origin_share(budget);
            let origin_usage = origin_storage_usage(&data, &origin);
            if origin_usage + new_bytes_len > share {
                let needed = origin_usage + new_bytes_len - share;
                evict_sole_owned_entries_for_origin(
                    &mut data,
                    self.config_dir.as_deref(),
                    &origin,
                    needed,
                );
                if origin_storage_usage(&data, &origin) + new_bytes_len > share {
                    // Eviction above already removed entries and deleted
                    // both their on-disk byte and metadata files
                    // per-entry as it went (see `evict_sole_owned_entries_for_origin`),
                    // so nothing further needs persisting here on
                    // rejection; see this module's doc comment on
                    // per-entry persistence.
                    return VerifyAndStoreOutcome::QuotaExceeded {
                        quota_bytes: share,
                        requested_bytes: new_bytes_len,
                    };
                }
            }
        }

        let used_after_self_eviction = total_bytes_used(&data);
        if used_after_self_eviction + new_bytes_len > budget {
            let needed = used_after_self_eviction + new_bytes_len - budget;
            evict_globally_lru(&mut data, self.config_dir.as_deref(), needed);
            if total_bytes_used(&data) + new_bytes_len > budget {
                // Same reasoning as the per-origin-share rejection above.
                return VerifyAndStoreOutcome::QuotaExceeded {
                    quota_bytes: budget,
                    requested_bytes: new_bytes_len,
                };
            }
        }

        // Internal-only safety net: the nominal budget above is a stable
        // fraction of *total* disk capacity (see
        // `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc comment for why), so it
        // can still nominally "allow" a write that would not actually
        // fit in real, currently available space -- COS must not attempt
        // that regardless of what the nominal budget says. Reused
        // `evict_globally_lru` first, same as the nominal-budget check
        // above, since a genuinely low-disk condition is exactly the
        // kind of storage pressure that check is meant for. Critically,
        // the reported `quota_bytes` on rejection is still the stable
        // nominal `budget`, never the real free-space figure: a
        // rejection caused by genuinely low disk space must stay
        // indistinguishable from an ordinary nominal-budget rejection,
        // or this safety net itself would become the fingerprinting
        // vector the nominal budget's design was trying to avoid.
        if new_bytes_len > self.query_free_disk_space() {
            let needed = new_bytes_len - self.query_free_disk_space();
            evict_globally_lru(&mut data, self.config_dir.as_deref(), needed);
            if new_bytes_len > self.query_free_disk_space() {
                return VerifyAndStoreOutcome::QuotaExceeded {
                    quota_bytes: budget,
                    requested_bytes: new_bytes_len,
                };
            }
        }

        self.persist_entry_bytes(&key, &bytes);

        let entry = data
            .entries
            .entry(key.clone())
            .or_insert_with(|| CosEntry {
                bytes: None,
                state: CosEntryState::Pending,
                origins: CosOrigins::SameSiteOnly,
                storing_origins: HashSet::new(),
                pending_since_unix_secs: unix_now_secs(),
                last_read_unix_secs: unix_now_secs(),
            });

        entry.bytes = Some(StoredEntryBytes { bytes, type_string });
        entry.state = CosEntryState::Written;
        entry.last_read_unix_secs = unix_now_secs();
        entry.storing_origins.insert(origin);
        upgrade_resource_visibility(entry, requested_origins);
        self.persist_entry(&key, entry);

        VerifyAndStoreOutcome::Success
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

/// Fraction of (free disk space + bytes already used by Cross-Origin
/// Storage) this implementation allows itself to occupy; see
/// `storage_budget`. Not spec-mandated -- the explainer only says user
/// agents "could delete files automatically based on, for example, a
/// least recently used approach" under storage pressure, with no numeric
/// guidance -- so, like `servo-storage`'s own `STORAGE_SHELF_QUOTA_BYTES`
/// (`components/storage/client_storage.rs`, matching Firefox's
/// documented 10 GiB group limit), this follows real browser precedent
/// rather than inventing a number: per
/// <https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria>,
/// Chromium-based browsers allow an origin up to 60% of **total** disk
/// size, and Safari/WebKit uses a comparable ~60% figure for browser
/// apps (Firefox is more conservative: 10%, capped at a fixed 10 GiB
/// group limit). This follows Chrome/Safari's more generous figure
/// rather than Firefox's, since COS explicitly targets much larger
/// content (multi-gigabyte AI model weights) than typical Storage API
/// usage.
///
/// Deliberately based on **total** disk capacity, not *available* free
/// space, matching all three of those engines: as the same MDN page
/// puts it, "it might not actually be possible for the origin to reach
/// its quota because it is calculated based on the hard drive total
/// size, not the currently available disk space. This is done for
/// security reasons, to avoid fingerprinting." Total capacity is stable
/// (it doesn't change as other things fill up the disk), so exposing it
/// in a `QuotaExceededError` (see `VerifyAndStoreOutcome::QuotaExceeded`)
/// doesn't let a page infer real-time free space the way a live
/// free-space-derived number would. Real available space still matters
/// -- COS should not attempt to write past what the OS can actually
/// provide -- but that check is a silent, internal-only safety net (see
/// `query_free_disk_space`'s use in `verify_and_store`) that never
/// surfaces its own number to script, for the same reason.
const GLOBAL_STORAGE_BUDGET_FRACTION: f64 = 0.6;

/// Fraction of the *current* global budget (see `storage_budget`) any
/// single requesting origin's own storing-origin usage may occupy; see
/// `origin_storage_usage` and `evict_sole_owned_entries_for_origin`.
/// Exists so one origin writing a lot cannot force eviction of a
/// *different* origin's entries merely by writing more recently -- once
/// an origin is at its own share, further writes evict only that same
/// origin's own sole-owned entries (see that function's doc comment for
/// why "sole-owned" specifically), never anyone else's. 20% means up to
/// five origins can each hold a full share simultaneously before the
/// *global* budget (not any single origin) becomes the binding
/// constraint, which then falls back to plain cross-origin LRU (see
/// `evict_globally_lru`) -- fair in that scenario, since it reflects
/// genuine multi-tenant demand rather than one origin crowding out
/// another.
const PER_ORIGIN_STORAGE_SHARE_FRACTION: f64 = 0.2;

/// Total bytes of every `Written` entry's stored bytes across the whole
/// registry (entry bytes already live in memory once loaded; see this
/// module's doc comment on `CrossOriginStorageStore::new`, so this is a
/// cheap in-memory sum, not a disk scan).
fn total_bytes_used(data: &CosRegistryData) -> u64 {
    data.entries
        .values()
        .map(|entry| entry.bytes.as_ref().map_or(0, |bytes| bytes.bytes.len() as u64))
        .sum()
}

/// Total bytes of every entry `origin` is a storing origin for. An entry
/// with multiple storing origins (the same content independently
/// verified by more than one writer) counts its full size against
/// *every* one of them, not divided up: this measures how much each
/// origin has itself chosen to write/verify, not how many physical bytes
/// are on disk, and dividing it up would let an origin get "free" quota
/// usage by re-verifying content someone else already stored.
fn origin_storage_usage(data: &CosRegistryData, origin: &ImmutableOrigin) -> u64 {
    data.entries
        .values()
        .filter(|entry| entry.storing_origins.contains(origin))
        .map(|entry| entry.bytes.as_ref().map_or(0, |bytes| bytes.bytes.len() as u64))
        .sum()
}

/// The current global storage budget in bytes: a stable fraction of
/// **total** disk capacity; see `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc
/// comment for why total capacity, not available free space, is the
/// right basis (matching real browser precedent, and avoiding both a
/// fingerprinting vector and a self-cannibalizing feedback loop where
/// COS's own growth would otherwise shrink its own future budget).
fn storage_budget(total_disk_space: u64) -> u64 {
    (total_disk_space as f64 * GLOBAL_STORAGE_BUDGET_FRACTION) as u64
}

/// `origin`'s share of `budget`; see `PER_ORIGIN_STORAGE_SHARE_FRACTION`.
fn per_origin_share(budget: u64) -> u64 {
    (budget as f64 * PER_ORIGIN_STORAGE_SHARE_FRACTION) as u64
}

/// Evicts `origin`'s own *sole-owned* `Written` entries (ones where it
/// is the only storing origin), oldest-last-read-first, until at least
/// `bytes_needed` are freed or there are no more eligible entries.
/// Deliberately never touches an entry with more than one storing
/// origin, even one `origin` is a co-owner of: `origin` writing enough
/// to hit its own share must never be able to delete a *different*
/// origin's data as a side effect, and a shared entry is, by
/// definition, partly someone else's. If this cannot free enough
/// (because `origin`'s remaining usage is all in shared entries), the
/// caller rejects the write instead of reaching into shared data.
fn evict_sole_owned_entries_for_origin(
    data: &mut CosRegistryData,
    config_dir: Option<&Path>,
    origin: &ImmutableOrigin,
    bytes_needed: u64,
) {
    let mut candidates: Vec<(String, u64, u64)> = data
        .entries
        .iter()
        .filter(|(_, entry)| {
            entry.state == CosEntryState::Written &&
                entry.storing_origins.len() == 1 &&
                entry.storing_origins.contains(origin)
        })
        .map(|(key, entry)| {
            let size = entry.bytes.as_ref().map_or(0, |bytes| bytes.bytes.len() as u64);
            (key.clone(), size, entry.last_read_unix_secs)
        })
        .collect();
    candidates.sort_by_key(|(_, _, last_read_unix_secs)| *last_read_unix_secs);

    let mut freed = 0u64;
    for (key, size, _) in candidates {
        if freed >= bytes_needed {
            break;
        }
        data.entries.remove(&key);
        delete_entry_bytes_file(config_dir, &key);
        delete_entry_metadata_file(config_dir, &key);
        freed += size;
    }
}

/// Evicts `Written` entries regardless of owner, oldest-last-read-first,
/// until at least `bytes_needed` are freed or there are no more entries.
/// The fallback for when several *different* origins, each individually
/// within its own `PER_ORIGIN_STORAGE_SHARE_FRACTION` share, collectively
/// still exceed the global budget -- ordinary multi-tenant storage
/// pressure, not one origin's abuse, so plain least-recently-used (as
/// the explainer itself suggests for storage pressure generally) is a
/// fair policy here.
fn evict_globally_lru(data: &mut CosRegistryData, config_dir: Option<&Path>, bytes_needed: u64) {
    let mut candidates: Vec<(String, u64, u64)> = data
        .entries
        .iter()
        .filter(|(_, entry)| entry.state == CosEntryState::Written)
        .map(|(key, entry)| {
            let size = entry.bytes.as_ref().map_or(0, |bytes| bytes.bytes.len() as u64);
            (key.clone(), size, entry.last_read_unix_secs)
        })
        .collect();
    candidates.sort_by_key(|(_, _, last_read_unix_secs)| *last_read_unix_secs);

    let mut freed = 0u64;
    for (key, size, _) in candidates {
        if freed >= bytes_needed {
            break;
        }
        data.entries.remove(&key);
        delete_entry_bytes_file(config_dir, &key);
        delete_entry_metadata_file(config_dir, &key);
        freed += size;
    }
}

/// Deletes an evicted entry's per-entry bytes file, if `config_dir` is
/// set (see this module's doc comment on why entry bytes live in their
/// own file). A missing file is not a warning-worthy problem (nothing to
/// clean up); any other error is, since it means eviction "freed" bytes
/// that are still actually on disk.
fn delete_entry_bytes_file(config_dir: Option<&Path>, key: &str) {
    let Some(dir) = config_dir else {
        return;
    };
    let path = entry_bytes_path(dir, key);
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            warn!(
                "Could not delete evicted Cross-Origin Storage entry bytes at {}: {err}",
                path.display()
            );
        }
    }
}

/// Deletes an evicted (or abandoned) entry's per-entry metadata file, if
/// `config_dir` is set; the sibling of `delete_entry_bytes_file`, called
/// immediately as part of eviction/abandonment itself so an entry that
/// should be gone doesn't remain discoverable on the next
/// `CrossOriginStorageStore::new()`. A missing file is not a
/// warning-worthy problem; any other error is.
fn delete_entry_metadata_file(config_dir: Option<&Path>, key: &str) {
    let Some(dir) = config_dir else {
        return;
    };
    let path = entry_metadata_path(dir, key);
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            warn!(
                "Could not delete evicted Cross-Origin Storage entry metadata at {}: {err}",
                path.display()
            );
        }
    }
}

/// The disk (per `sysinfo`) whose mount point is the longest matching
/// prefix of `path`, so a nested mount (e.g. a separate partition
/// mounted under the config directory's ancestry) is preferred over a
/// shorter, less specific match. Shared by `free_disk_space_at` and
/// `total_disk_space_at`.
fn disk_containing<'disks>(disks: &'disks sysinfo::Disks, path: &Path) -> Option<&'disks sysinfo::Disk> {
    disks
        .list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
}

/// The available (free) space, in bytes, on whichever mounted
/// filesystem contains `path`. Used only as `verify_and_store`'s
/// internal, never-reported safety net (see
/// `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc comment for why the *nominal*
/// budget is based on `total_disk_space_at` instead).
fn free_disk_space_at(path: &Path) -> u64 {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disk_containing(&disks, path)
        .map(|disk| disk.available_space())
        .unwrap_or(0)
}

/// The total capacity, in bytes, of whichever mounted filesystem
/// contains `path`. This, not `free_disk_space_at`, is the basis for
/// COS's nominal storage budget; see `GLOBAL_STORAGE_BUDGET_FRACTION`'s
/// doc comment for why.
fn total_disk_space_at(path: &Path) -> u64 {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disk_containing(&disks, path)
        .map(|disk| disk.total_space())
        .unwrap_or(0)
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

    /// A `Written` entry of `size` bytes, for storage-budget tests that
    /// only care about size/ownership/recency, not real hash-verified
    /// content.
    fn written_entry(
        size: usize,
        storing_origins: HashSet<ImmutableOrigin>,
        last_read_unix_secs: u64,
    ) -> CosEntry {
        CosEntry {
            bytes: Some(StoredEntryBytes {
                bytes: vec![0u8; size],
                type_string: String::new(),
            }),
            state: CosEntryState::Written,
            origins: CosOrigins::SameSiteOnly,
            storing_origins,
            pending_since_unix_secs: 0,
            last_read_unix_secs,
        }
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

        assert!(matches!(
            store.verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None),
            VerifyAndStoreOutcome::Success
        ));

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
        assert!(matches!(
            store.verify_and_store(&h, b"wrong bytes".to_vec(), "text/plain".to_owned(), writer, None),
            VerifyAndStoreOutcome::HashMismatch
        ));
    }

    #[test]
    fn same_site_only_entry_is_not_readable_by_a_different_origin() {
        let store = store();
        let bytes = b"same-site-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let other = origin("https://other.example");

        assert!(matches!(
            store.verify_and_store(&h, bytes, "text/plain".to_owned(), writer, None),
            VerifyAndStoreOutcome::Success
        ));

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

        assert!(matches!(
            store.verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer, None),
            VerifyAndStoreOutcome::Success
        ));

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

        assert!(matches!(
            store.verify_and_store(&h, bytes, "text/plain".to_owned(), writer, None),
            VerifyAndStoreOutcome::Success
        ));

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

        assert!(matches!(
            store.verify_and_store(
                &h,
                bytes,
                "text/plain".to_owned(),
                writer,
                Some(RequestedOrigins::List(vec![listed.clone()])),
            ),
            VerifyAndStoreOutcome::Success
        ));

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
            last_read_unix_secs: 0,
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
            last_read_unix_secs: 0,
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
            last_read_unix_secs: 0,
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
        assert!(matches!(
            store.verify_and_store(
                &h,
                content,
                "text/plain".to_owned(),
                second_writer,
                Some(RequestedOrigins::List(vec![new_origin.clone()])),
            ),
            VerifyAndStoreOutcome::Success
        ));

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

        assert!(matches!(
            store.verify_and_store(
                &h,
                bytes,
                "text/plain".to_owned(),
                writer,
                Some(RequestedOrigins::Wildcard),
            ),
            VerifyAndStoreOutcome::Success
        ));

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
                last_read_unix_secs: 0,
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
            last_read_unix_secs: 0,
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
            last_read_unix_secs: 0,
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

        assert!(matches!(
            store.verify_and_store(
                &h,
                bytes.clone(),
                "text/plain".to_owned(),
                writer.clone(),
                Some(RequestedOrigins::Wildcard),
            ),
            VerifyAndStoreOutcome::Success
        ));

        let second_writer = origin("https://second-writer.example");
        assert!(matches!(
            store.verify_and_store(
                &h,
                bytes,
                "text/plain".to_owned(),
                second_writer,
                Some(RequestedOrigins::List(vec![origin("https://narrow.example")])),
            ),
            VerifyAndStoreOutcome::Success
        ));

        let data = store.data.read();
        let entry = data.entries.get(&registry_key(&h)).unwrap();
        assert!(matches!(entry.origins, CosOrigins::Wildcard));
    }

    #[test]
    fn fresh_pending_entry_blocks_readers_with_pending_write() {
        let store = store();
        let h = hash("SHA-256", &"1".repeat(64));
        let creator = origin("https://creator.example");
        let reader = origin("https://reader.example");

        store.complete_a_create_request(&h, &creator, None);

        assert!(matches!(
            store.complete_a_read_request(&h, &reader),
            CosReadOutcome::PendingWrite
        ));
    }

    #[test]
    fn stale_pending_entry_reads_as_not_found_instead_of_pending_write() {
        let store = store();
        let h = hash("SHA-256", &"2".repeat(64));
        let creator = origin("https://creator.example");
        let reader = origin("https://reader.example");

        store.complete_a_create_request(&h, &creator, None);
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
        store.complete_a_create_request(&h, &writer, None);
        backdate_pending_entry(&store, &h);

        // A second create request for the same hash must not stay stuck
        // behind the stale entry -- it gets a fresh one, and a real write
        // against it succeeds normally.
        store.complete_a_create_request(&h, &writer, None);
        let bytes = b"retried after abandonment".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        store.complete_a_create_request(&h, &writer, None);
        assert!(matches!(
            store.verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None),
            VerifyAndStoreOutcome::Success
        ));

        match store.complete_a_read_request(&h, &writer) {
            CosReadOutcome::Found { bytes: found, .. } => assert_eq!(found, bytes),
            other => panic!("expected the retried write to succeed, got {other:?}"),
        }
    }

    #[test]
    fn abandon_pending_write_removes_a_still_pending_entry_immediately() {
        let store = store();
        let h = hash("SHA-256", &"4".repeat(64));
        let creator = origin("https://creator.example");
        let reader = origin("https://reader.example");

        store.complete_a_create_request(&h, &creator, None);
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

        assert!(matches!(
            store.verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None),
            VerifyAndStoreOutcome::Success
        ));
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
            assert!(matches!(
                store.verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None),
                VerifyAndStoreOutcome::Success
            ));
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

    #[test]
    fn a_genuine_read_persists_last_read_unix_secs_so_it_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("servo-cos-registry-test-{}", uuid_like_suffix()));
        std::fs::create_dir_all(&dir).unwrap();

        let older_bytes = b"written-first".to_vec();
        let older_hex = compute_hex_digest("SHA-256", &older_bytes).unwrap();
        let older_hash = hash("SHA-256", &older_hex);

        let newer_bytes = b"written-second".to_vec();
        let newer_hex = compute_hex_digest("SHA-256", &newer_bytes).unwrap();
        let newer_hash = hash("SHA-256", &newer_hex);

        let writer = origin("https://writer.example");

        {
            let store = CrossOriginStorageStore::new(Some(dir.clone()));
            assert!(matches!(
                store.verify_and_store(
                    &older_hash,
                    older_bytes,
                    "text/plain".to_owned(),
                    writer.clone(),
                    None
                ),
                VerifyAndStoreOutcome::Success
            ));

            // 1-second `unix_now_secs()`/mtime resolution: sleep long
            // enough between each step that the timestamps below are
            // observably ordered.
            std::thread::sleep(std::time::Duration::from_millis(1100));

            assert!(matches!(
                store.verify_and_store(
                    &newer_hash,
                    newer_bytes,
                    "text/plain".to_owned(),
                    writer.clone(),
                    None
                ),
                VerifyAndStoreOutcome::Success
            ));

            std::thread::sleep(std::time::Duration::from_millis(1100));

            // Read the entry that was written *first*, well after the
            // other one was written -- if the read is correctly
            // persisted, this makes the first-written entry the more
            // recently *used* one, the opposite of write order.
            match store.complete_a_read_request(&older_hash, &writer) {
                CosReadOutcome::Found { .. } => {},
                other => panic!("expected the older entry to be found, got {other:?}"),
            }
        }

        // A fresh store, loaded from disk only: without persisting the
        // read above, `last_read_unix_secs` would only ever reflect each
        // entry's *write* time, so the second-written entry would
        // incorrectly look like the more recently used one here.
        let reloaded = CrossOriginStorageStore::new(Some(dir.clone()));
        let data = reloaded.data.read();
        let older_last_read = data.entries.get(&registry_key(&older_hash)).unwrap().last_read_unix_secs;
        let newer_last_read = data.entries.get(&registry_key(&newer_hash)).unwrap().last_read_unix_secs;
        assert!(
            older_last_read > newer_last_read,
            "expected the entry read most recently to have the greater persisted \
             last_read_unix_secs even though it was written first \
             (older_last_read={older_last_read}, newer_last_read={newer_last_read})"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_budget_is_60_percent_of_total_disk_space() {
        assert_eq!(storage_budget(1000), 600);
        assert_eq!(storage_budget(0), 0);
    }

    #[test]
    fn per_origin_share_is_20_percent_of_the_budget() {
        assert_eq!(per_origin_share(1000), 200);
    }

    #[test]
    fn total_bytes_used_sums_every_written_entrys_bytes() {
        let mut data = CosRegistryData::default();
        data.entries.insert("a".to_owned(), written_entry(10, HashSet::new(), 0));
        data.entries.insert("b".to_owned(), written_entry(25, HashSet::new(), 0));
        assert_eq!(total_bytes_used(&data), 35);
    }

    #[test]
    fn origin_storage_usage_only_counts_entries_the_origin_stores() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let mut data = CosRegistryData::default();
        data.entries
            .insert("owned-by-a".to_owned(), written_entry(10, HashSet::from([a.clone()]), 0));
        data.entries
            .insert("owned-by-b".to_owned(), written_entry(20, HashSet::from([b.clone()]), 0));
        data.entries.insert(
            "shared".to_owned(),
            written_entry(5, HashSet::from([a.clone(), b.clone()]), 0),
        );
        assert_eq!(origin_storage_usage(&data, &a), 15); // 10 + 5
        assert_eq!(origin_storage_usage(&data, &b), 25); // 20 + 5
    }

    #[test]
    fn evict_sole_owned_entries_for_origin_never_touches_a_shared_entry() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let mut data = CosRegistryData::default();
        data.entries
            .insert("sole-owned".to_owned(), written_entry(10, HashSet::from([a.clone()]), 100));
        data.entries.insert(
            "shared".to_owned(),
            written_entry(50, HashSet::from([a.clone(), b.clone()]), 50),
        );

        // Ask for more than the sole-owned entry alone can free -- if
        // shared entries were eligible, evicting "shared" too would
        // easily cover it.
        evict_sole_owned_entries_for_origin(&mut data, None, &a, 30);

        assert!(!data.entries.contains_key("sole-owned"));
        // "shared" must survive: b also depends on it, and self-eviction
        // must never delete data that isn't exclusively the flooding
        // origin's own.
        assert!(data.entries.contains_key("shared"));
    }

    #[test]
    fn evict_sole_owned_entries_for_origin_evicts_oldest_first_until_enough_is_freed() {
        let a = origin("https://a.example.com");
        let mut data = CosRegistryData::default();
        data.entries
            .insert("oldest".to_owned(), written_entry(10, HashSet::from([a.clone()]), 1));
        data.entries
            .insert("middle".to_owned(), written_entry(10, HashSet::from([a.clone()]), 2));
        data.entries
            .insert("newest".to_owned(), written_entry(10, HashSet::from([a.clone()]), 3));

        evict_sole_owned_entries_for_origin(&mut data, None, &a, 15);

        assert!(!data.entries.contains_key("oldest"));
        assert!(!data.entries.contains_key("middle"));
        assert!(data.entries.contains_key("newest"));
    }

    #[test]
    fn evict_globally_lru_evicts_oldest_regardless_of_owner() {
        let a = origin("https://a.example.com");
        let b = origin("https://b.example.com");
        let mut data = CosRegistryData::default();
        data.entries
            .insert("as-oldest".to_owned(), written_entry(10, HashSet::from([a.clone()]), 1));
        data.entries
            .insert("bs-newer".to_owned(), written_entry(10, HashSet::from([b.clone()]), 2));

        evict_globally_lru(&mut data, None, 10);

        assert!(!data.entries.contains_key("as-oldest"));
        assert!(data.entries.contains_key("bs-newer"));
    }

    #[test]
    fn one_origin_writing_a_lot_never_evicts_a_different_origins_entry() {
        // Large enough that the *global* budget never becomes the
        // binding constraint here -- this test is specifically about
        // the *per-origin share* protecting other origins, isolated from
        // the (intentionally different, "fair" by design) global
        // fallback eviction; see
        // `evict_globally_lru_evicts_oldest_regardless_of_owner` for that
        // other, expected case.
        let mut store = store();
        store.set_fake_total_disk_space(100_000);

        let flooder = origin("https://flooder.example.com");
        let victim = origin("https://victim.example.com");

        let victim_bytes = b"victim-data".to_vec();
        let victim_hex = compute_hex_digest("SHA-256", &victim_bytes).unwrap();
        let victim_hash = hash("SHA-256", &victim_hex);
        assert!(matches!(
            store.verify_and_store(
                &victim_hash,
                victim_bytes.clone(),
                "text/plain".to_owned(),
                victim.clone(),
                None
            ),
            VerifyAndStoreOutcome::Success
        ));

        // The flooder writes many large, distinct (real hash/content
        // pairs, not fabricated) entries -- each one big enough that a
        // handful of them exceed the flooder's own 20% share, forcing
        // repeated self-eviction of the flooder's *own* earlier entries.
        for i in 0..50 {
            let bytes = format!("flood-{i}-{}", "x".repeat(1000)).into_bytes();
            let hex = compute_hex_digest("SHA-256", &bytes).unwrap();
            let h = hash("SHA-256", &hex);
            store.verify_and_store(&h, bytes, "text/plain".to_owned(), flooder.clone(), None);
        }

        // Repeated self-eviction must have kept the flooder's own
        // footprint well under all 50 entries it attempted (proving
        // eviction actually happened, not a no-op). Which *specific*
        // flood entries got evicted isn't asserted: `last_read_unix_secs`
        // has only 1-second resolution, and this loop writes 50 entries
        // within a single wall-clock second, so oldest-first tie-breaking
        // among same-timestamp entries comes down to `HashMap` iteration
        // order, not creation order -- not deterministic here, though a
        // real, slower-paced usage pattern wouldn't have that ambiguity.
        let flooder_entry_count = {
            let data = store.data.read();
            data.entries
                .values()
                .filter(|entry| entry.storing_origins.contains(&flooder))
                .count()
        };
        assert!(
            flooder_entry_count < 50,
            "expected repeated self-eviction to bound the flooder's own entry count, got {flooder_entry_count}"
        );

        // The victim's entry, which the flooder never touched, must
        // still be there regardless of which flood entries got evicted.
        assert!(matches!(
            store.complete_a_read_request(&victim_hash, &victim),
            CosReadOutcome::Found { .. }
        ));
    }

    #[test]
    fn consume_write_token_allows_up_to_capacity_then_denies() {
        let store = store();
        let o = origin("https://writer.example");
        let mut allowed = 0;
        for _ in 0..(WRITE_BUDGET_CAPACITY as usize) {
            if store.consume_write_token(&o) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, WRITE_BUDGET_CAPACITY as usize);
        assert!(!store.consume_write_token(&o));
    }

    #[test]
    fn complete_a_create_request_shares_the_write_budget_with_verify_and_store() {
        let store = store();
        let o = origin("https://origin.example.com");

        // Exhaust the entire write budget via create() calls alone --
        // each a distinct hash, so every one is a genuine,
        // budget-consuming call, not a no-op the fresh-entry check would
        // skip regardless.
        for i in 0..(WRITE_BUDGET_CAPACITY as usize) {
            let h = hash("SHA-256", &format!("{i:064x}"));
            store.complete_a_create_request(&h, &o, None);
        }

        // A real write attempt from the same origin must now be
        // rate-limited too: create() and verify_and_store() share one
        // budget, not two separate ones.
        let bytes = b"over-shared-write-budget".to_vec();
        let hex = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &hex);
        assert!(matches!(
            store.verify_and_store(&h, bytes, "text/plain".to_owned(), o, None),
            VerifyAndStoreOutcome::RateLimited
        ));
    }

    #[test]
    fn complete_a_create_request_is_a_no_op_when_write_budget_exhausted() {
        let store = store();
        let o = origin("https://origin.example.com");
        for _ in 0..(WRITE_BUDGET_CAPACITY as usize) {
            store.consume_write_token(&o);
        }

        let h = hash("SHA-256", &"6".repeat(64));
        store.complete_a_create_request(&h, &o, None);

        // No entry should have been created at all: the call was
        // silently dropped for being over budget, before ever touching
        // the registry.
        let data = store.data.read();
        assert!(!data.entries.contains_key(&registry_key(&h)));
    }

    #[test]
    fn complete_a_create_request_does_not_rewrite_the_registry_file_for_a_no_op_repeat() {
        let dir = std::env::temp_dir().join(format!("servo-cos-registry-test-{}", uuid_like_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = CrossOriginStorageStore::new(Some(dir.clone()));
        let creator = origin("https://creator.example.com");
        let h = hash("SHA-256", &"7".repeat(64));

        store.complete_a_create_request(&h, &creator, None);
        let entry_path = entry_metadata_path(&dir, &registry_key(&h));
        let mtime_after_first_create = std::fs::metadata(&entry_path).unwrap().modified().unwrap();

        // Some filesystems only have 1-second mtime resolution; wait
        // long enough that a real rewrite would produce an observably
        // different mtime.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // A second create() for the same hash, which already has a
        // fresh Pending entry, is a genuine no-op -- its entry file
        // must not be rewritten for it.
        store.complete_a_create_request(&h, &creator, None);
        let mtime_after_second_create = std::fs::metadata(&entry_path).unwrap().modified().unwrap();

        assert_eq!(mtime_after_first_create, mtime_after_second_create);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_and_store_rejects_with_rate_limited_when_write_budget_exhausted() {
        let store = store();
        let o = origin("https://writer.example.com");
        for _ in 0..(WRITE_BUDGET_CAPACITY as usize) {
            store.consume_write_token(&o);
        }

        let bytes = b"over-write-budget".to_vec();
        let hex = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &hex);
        assert!(matches!(
            store.verify_and_store(&h, bytes, "text/plain".to_owned(), o, None),
            VerifyAndStoreOutcome::RateLimited
        ));
    }

    #[test]
    fn verify_and_store_rejects_with_quota_exceeded_when_nothing_can_free_enough_room() {
        let mut store = store();
        // budget = 0.6 * 100 = 60 bytes; the write below is far bigger
        // than that, and there is nothing yet to evict to make room.
        store.set_fake_total_disk_space(100);

        let bytes = vec![0u8; 1000];
        let hex = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &hex);
        let o = origin("https://writer.example.com");

        match store.verify_and_store(&h, bytes, "text/plain".to_owned(), o, None) {
            VerifyAndStoreOutcome::QuotaExceeded { .. } => {},
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
    }

    #[test]
    fn real_low_free_space_still_rejects_but_never_reports_the_real_number() {
        let mut store = store();
        // A huge nominal budget (plenty of "total disk")...
        store.set_fake_total_disk_space(1_000_000_000);
        // ...but almost no real free space. The internal safety net must
        // still reject the write; critically, the reported `quota_bytes`
        // must be the stable *nominal* budget, not the tiny real
        // free-space figure -- reporting the real number here would
        // reintroduce exactly the fingerprinting vector
        // `GLOBAL_STORAGE_BUDGET_FRACTION`'s doc comment explains why the
        // nominal budget avoids.
        store.set_fake_free_disk_space(10);

        let bytes = vec![0u8; 1000];
        let hex = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &hex);
        let o = origin("https://writer.example.com");

        let expected_nominal_budget = storage_budget(1_000_000_000);
        match store.verify_and_store(&h, bytes, "text/plain".to_owned(), o, None) {
            VerifyAndStoreOutcome::QuotaExceeded { quota_bytes, .. } => {
                assert_eq!(
                    quota_bytes, expected_nominal_budget,
                    "must report the stable nominal budget, not the real free-space figure"
                );
            },
            other => panic!("expected QuotaExceeded from the real-free-space safety net, got {other:?}"),
        }
    }

    #[test]
    fn eviction_during_a_rejected_write_is_still_persisted_to_disk() {
        let dir = std::env::temp_dir().join(format!("servo-cos-registry-test-{}", uuid_like_suffix()));
        let a = origin("https://a.example.com");
        let small_bytes = b"small".to_vec();
        let small_hex = compute_hex_digest("SHA-256", &small_bytes).unwrap();
        let small_hash = hash("SHA-256", &small_hex);

        {
            let mut store = CrossOriginStorageStore::new(Some(dir.clone()));
            store.set_fake_total_disk_space(100);

            // First write: small, fits comfortably within a's share.
            assert!(matches!(
                store.verify_and_store(&small_hash, small_bytes.clone(), "text/plain".to_owned(), a.clone(), None),
                VerifyAndStoreOutcome::Success
            ));

            // Second write: alone bigger than a's entire share, even
            // after evicting everything a owns -- forces eviction of
            // the first entry (to try to make room) but is still
            // rejected, since the new entry alone doesn't fit either.
            let huge_bytes = vec![0u8; 1000];
            let huge_hex = compute_hex_digest("SHA-256", &huge_bytes).unwrap();
            let huge_hash = hash("SHA-256", &huge_hex);
            match store.verify_and_store(&huge_hash, huge_bytes, "text/plain".to_owned(), a.clone(), None) {
                VerifyAndStoreOutcome::QuotaExceeded { .. } => {},
                other => panic!("expected QuotaExceeded, got {other:?}"),
            }

            // In-memory, the small entry is already gone (evicted while
            // trying to make room, even though it wasn't enough).
            assert!(matches!(
                store.complete_a_read_request(&small_hash, &a),
                CosReadOutcome::NotFound
            ));
        }

        // A *fresh* store loaded from the same config_dir: if eviction
        // hadn't deleted the small entry's metadata file, this would
        // still find it, even though its bytes file was already deleted.
        let reloaded = CrossOriginStorageStore::new(Some(dir.clone()));
        assert!(matches!(
            reloaded.complete_a_read_request(&small_hash, &a),
            CosReadOutcome::NotFound
        ));

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
