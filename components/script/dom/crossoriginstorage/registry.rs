/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The Cross-Origin Storage registry
//! (<https://wicg.github.io/cross-origin-storage/#cos-entries>),
//! implementing the actual spec algorithms: the entry state machine
//! (pending/written), `origins` scoping, storing-origins bookkeeping,
//! availability gating, visibility-upgrade merging
//! (<https://wicg.github.io/cross-origin-storage/#resource-visibility-upgrades>),
//! and hash verification on write
//! (<https://wicg.github.io/cross-origin-storage/#verify-and-store>).
//!
//! This replaces `stub_registry` (removed in this change) as the backing
//! store for `CrossOriginStorageManager`. What changed: the algorithms
//! above are now real, spec-referenced implementations, not a bare
//! `HashMap` lookup.
//!
//! What is still NOT real, and should not be assumed to be:
//! - **Storage**: `thread_local!`, in-memory only. Not persisted across
//!   navigations, tabs, or restarts. Not shared across script threads,
//!   processes, or profiles. A conformant implementation needs the Storage
//!   Service (or equivalent), profile-scoped and durable.
//! - **Public Hash List**: not implemented. `is_on_public_hash_list()`
//!   always returns `false`, which means a `"*"`-scoped entry can never be
//!   disclosed to an origin outside its storing origins. This fails
//!   closed -- an empty/absent PHL is a valid PHL state per spec, so this
//!   is not a spec violation -- but it does mean global disclosure is
//!   untestable until a real PHL is wired in.
//! - **GREASE'ing** (spec 7.4): not implemented; optional per spec.
//! - **"Same site"** (used by the `origins: null` / same-site-only case):
//!   approximated here as same-*origin*, which is strictly more
//!   restrictive than the real, registrable-domain-based "same site"
//!   definition. This under-approximates disclosure (fewer things are
//!   considered same-site than really are), which is the safe direction
//!   to be wrong in, but it is not spec-correct. Replace with a real same
//!   site check.
//! - **`maximum origins list length`** (spec 5.1): not enforced, at
//!   either the immediate-validation or later-merge call site.
//! - **Per-origin write quota** (spec 5.1): not enforced.
//! - **Rate limiting / probing defenses** (spec 7.2): not implemented.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use aws_lc_rs::digest;
use servo_url::ImmutableOrigin;

use super::hash::CosHash;

/// A written [COS entry](https://wicg.github.io/cross-origin-storage/#cos-entry)'s
/// bytes. Deliberately a plain, `Clone`-able struct of our own rather than
/// `servo_constellation_traits::BlobImpl` (which does not implement
/// `Clone` by design: each `BlobImpl` carries its own identity via
/// `BlobId`). Callers construct a fresh `BlobImpl::new_from_bytes(...)` per
/// read instead.
#[derive(Clone)]
pub(crate) struct EntryBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) type_string: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CosEntryState {
    Pending,
    Written,
}

/// A COS entry's actual, at-rest `origins` scope
/// (<https://wicg.github.io/cross-origin-storage/#cos-entry-origins>).
/// Always exactly one of these three; never "unset" -- an entry that has
/// never had `options.origins` supplied is `SameSiteOnly`, not absent.
#[derive(Clone)]
enum CosOrigins {
    Wildcard,
    List(Vec<ImmutableOrigin>),
    SameSiteOnly,
}

/// The `origins` value *requested* via `options.origins` on a create call.
/// Distinct from `CosOrigins`: `None` here means the option was omitted
/// entirely (per
/// <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>,
/// this "never narrows an existing entry; it only requests same-site
/// availability, which every entry already has at least as much of"),
/// which is different from an entry's at-rest scope, which is never
/// "unset".
#[derive(Clone, PartialEq)]
pub(crate) enum RequestedOrigins {
    Wildcard,
    List(Vec<ImmutableOrigin>),
}

struct CosEntry {
    bytes: Option<EntryBytes>,
    state: CosEntryState,
    origins: CosOrigins,
    storing_origins: HashSet<ImmutableOrigin>,
}

thread_local! {
    static REGISTRY: RefCell<HashMap<(String, String), CosEntry>> = RefCell::new(HashMap::new());
}

/// The outcome of `complete a read request`
/// (<https://wicg.github.io/cross-origin-storage/#complete-a-read-request>).
/// `NotFound` covers both true absence and gating denial, matching the
/// spec's deliberate refusal to let callers distinguish the two (see spec
/// section 7.3, "availability gating").
pub(crate) enum ReadOutcome {
    Found(EntryBytes),
    NotFound,
    /// The entry exists but a write is (notionally) still in progress.
    /// Reachable today: two `requestFileHandle({create: true})` calls for
    /// the same hash both completing before either write finishes.
    PendingWrite,
}

/// <https://wicg.github.io/cross-origin-storage/#complete-a-read-request>
pub(crate) fn complete_a_read_request(hash: &CosHash, origin: &ImmutableOrigin) -> ReadOutcome {
    REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let Some(entry) = registry.get(&hash.normalized_key()) else {
            return ReadOutcome::NotFound;
        };

        if entry.state == CosEntryState::Pending {
            return ReadOutcome::PendingWrite;
        }

        if !apply_availability_gating(entry, origin) {
            return ReadOutcome::NotFound;
        }

        match &entry.bytes {
            Some(bytes) => ReadOutcome::Found(bytes.clone()),
            // Unreachable in practice: `state == Written` is only ever set
            // alongside `bytes = Some(..)` in `verify_and_store`. Handled
            // defensively rather than asserted, since nothing prevents a
            // future edit from decoupling the two.
            None => ReadOutcome::NotFound,
        }
    })
}

/// <https://wicg.github.io/cross-origin-storage/#complete-a-create-request>
/// (registry half only; handle construction is the caller's job).
pub(crate) fn complete_a_create_request(hash: &CosHash, requested_origins: Option<RequestedOrigins>) {
    let normalized = normalize_requested_origins_for_new_entry(requested_origins);
    REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .entry(hash.normalized_key())
            .or_insert_with(|| CosEntry {
                bytes: None,
                state: CosEntryState::Pending,
                origins: normalized,
                storing_origins: HashSet::new(),
            });
    });
}

fn normalize_requested_origins_for_new_entry(requested: Option<RequestedOrigins>) -> CosOrigins {
    match requested {
        None => CosOrigins::SameSiteOnly,
        Some(RequestedOrigins::Wildcard) => CosOrigins::Wildcard,
        Some(RequestedOrigins::List(origins)) => CosOrigins::List(origins),
    }
}

/// <https://wicg.github.io/cross-origin-storage/#verify-and-store>
///
/// Returns `Err(())` on hash mismatch (the caller should reject with
/// `DataError`, per spec); `bytes` is left unmodified in that case (there
/// is nothing to modify: no entry is created or updated on a failed
/// verification).
pub(crate) fn verify_and_store(
    hash: &CosHash,
    bytes: Vec<u8>,
    type_string: String,
    origin: ImmutableOrigin,
    requested_origins: Option<RequestedOrigins>,
) -> Result<(), ()> {
    let Some(computed_hex) = compute_hex_digest(&hash.algorithm, &bytes) else {
        // Only reachable if a caller skipped `CosHash::validate()`, which
        // already rejects unrecognized algorithm names. Fail closed.
        return Err(());
    };
    if computed_hex != hash.value.to_ascii_lowercase() {
        return Err(());
    }

    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let entry = registry
            .entry(hash.normalized_key())
            .or_insert_with(|| CosEntry {
                bytes: None,
                state: CosEntryState::Pending,
                origins: CosOrigins::SameSiteOnly,
                storing_origins: HashSet::new(),
            });

        entry.bytes = Some(EntryBytes { bytes, type_string });
        entry.state = CosEntryState::Written;
        entry.storing_origins.insert(origin);
        upgrade_resource_visibility(entry, requested_origins);
    });

    Ok(())
}

/// <https://wicg.github.io/cross-origin-storage/#upgrade-resource-visibility>
fn upgrade_resource_visibility(entry: &mut CosEntry, requested_origins: Option<RequestedOrigins>) {
    // Step 1.
    let Some(requested) = requested_origins else {
        return;
    };

    // Step 2.
    if matches!(entry.origins, CosOrigins::Wildcard) {
        return;
    }

    match requested {
        // Step 3.
        RequestedOrigins::Wildcard => {
            entry.origins = CosOrigins::Wildcard;
        },
        RequestedOrigins::List(candidates) => match &mut entry.origins {
            // Step 4.
            CosOrigins::SameSiteOnly => {
                entry.origins = CosOrigins::List(candidates);
            },
            // Steps 5-7. Note: `maximum origins list length` is not
            // enforced here; see this module's doc comment.
            CosOrigins::List(existing) => {
                for candidate in candidates {
                    if !existing.contains(&candidate) {
                        existing.push(candidate);
                    }
                }
            },
            CosOrigins::Wildcard => unreachable!("handled by the step-2 early return above"),
        },
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

/// <https://wicg.github.io/cross-origin-storage/#apply-availability-gating>
///
/// Simplified: GREASE'ing (spec step 4, "if the user agent elects to apply
/// GREASE'ing...") is not implemented, so this is currently equivalent to
/// `determine_cos_disclosure` plus the storing-origins short-circuit,
/// rather than a distinct algorithm. Kept as a separate function so a
/// future GREASE'ing implementation has a single, correctly-placed call
/// site rather than needing to be threaded through every caller of
/// `determine_cos_disclosure`.
fn apply_availability_gating(entry: &CosEntry, origin: &ImmutableOrigin) -> bool {
    determine_cos_disclosure(entry, origin)
}

/// Always `false`; see this module's doc comment.
fn is_on_public_hash_list() -> bool {
    false
}

/// See this module's doc comment: same-origin, not real same-site.
fn is_same_site_approximation(a: &ImmutableOrigin, b: &ImmutableOrigin) -> bool {
    a == b
}

fn compute_hex_digest(algorithm: &str, bytes: &[u8]) -> Option<String> {
    let digest = match algorithm.to_ascii_uppercase().as_str() {
        "SHA-1" => digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, bytes),
        "SHA-256" => digest::digest(&digest::SHA256, bytes),
        "SHA-384" => digest::digest(&digest::SHA384, bytes),
        "SHA-512" => digest::digest(&digest::SHA512, bytes),
        _ => return None,
    };
    Some(
        digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
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

    fn origin(url: &str) -> ImmutableOrigin {
        ImmutableOrigin::new(&url::Url::parse(url).unwrap())
    }

    #[test]
    fn unknown_hash_reads_as_not_found() {
        clear_for_test();
        let h = hash("SHA-256", &"a".repeat(64));
        let o = origin("https://example.com");
        assert!(matches!(
            complete_a_read_request(&h, &o),
            ReadOutcome::NotFound
        ));
    }

    #[test]
    fn write_then_read_by_storing_origin_succeeds() {
        clear_for_test();
        let bytes = b"hello cos".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");

        assert!(
            verify_and_store(&h, bytes.clone(), "text/plain".to_owned(), writer.clone(), None)
                .is_ok()
        );

        match complete_a_read_request(&h, &writer) {
            ReadOutcome::Found(entry) => assert_eq!(entry.bytes, bytes),
            _ => panic!("expected the storing origin to read its own write back"),
        }
    }

    #[test]
    fn write_rejected_on_hash_mismatch() {
        clear_for_test();
        let h = hash("SHA-256", &"0".repeat(64));
        let writer = origin("https://writer.example");
        assert!(
            verify_and_store(&h, b"wrong bytes".to_vec(), "text/plain".to_owned(), writer, None)
                .is_err()
        );
    }

    #[test]
    fn same_site_only_entry_is_not_readable_by_a_different_origin() {
        clear_for_test();
        let bytes = b"same-site-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let other = origin("https://other.example");

        verify_and_store(&h, bytes, "text/plain".to_owned(), writer, None).unwrap();

        assert!(matches!(
            complete_a_read_request(&h, &other),
            ReadOutcome::NotFound
        ));
    }

    #[test]
    fn list_scoped_entry_is_readable_by_a_listed_origin() {
        clear_for_test();
        let bytes = b"list-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let listed = origin("https://listed.example");

        verify_and_store(
            &h,
            bytes,
            "text/plain".to_owned(),
            writer,
            Some(RequestedOrigins::List(vec![listed.clone()])),
        )
        .unwrap();

        assert!(matches!(
            complete_a_read_request(&h, &listed),
            ReadOutcome::Found(_)
        ));
    }

    #[test]
    fn wildcard_entry_is_not_readable_by_an_outside_origin_without_a_phl() {
        clear_for_test();
        let bytes = b"wildcard-scoped".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");
        let outsider = origin("https://outsider.example");

        verify_and_store(
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
            complete_a_read_request(&h, &outsider),
            ReadOutcome::NotFound
        ));
    }

    #[test]
    fn visibility_upgrade_never_downgrades_from_wildcard() {
        clear_for_test();
        let bytes = b"upgrade-test".to_vec();
        let computed = compute_hex_digest("SHA-256", &bytes).unwrap();
        let h = hash("SHA-256", &computed);
        let writer = origin("https://writer.example");

        verify_and_store(
            &h,
            bytes.clone(),
            "text/plain".to_owned(),
            writer.clone(),
            Some(RequestedOrigins::Wildcard),
        )
        .unwrap();

        // A second write requesting a narrower scope must not restrict
        // the already-"*"-scoped entry.
        let second_writer = origin("https://second-writer.example");
        verify_and_store(
            &h,
            bytes,
            "text/plain".to_owned(),
            second_writer,
            Some(RequestedOrigins::List(vec![origin("https://narrow.example")])),
        )
        .unwrap();

        REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let entry = registry.get(&h.normalized_key()).unwrap();
            assert!(matches!(entry.origins, CosOrigins::Wildcard));
        });
    }
}
