/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Wire types for the Cross-Origin Storage registry
//! (<https://wicg.github.io/cross-origin-storage/#cos-entries>), which
//! lives in the resource thread (see
//! `net::cross_origin_storage_thread::CrossOriginStorageStore`) rather
//! than per-script-thread, so that it is genuinely shared across script
//! threads/processes and can be persisted to disk. This mirrors
//! `filemanager_thread.rs`'s `FileManagerThreadMsg` in shape and in this
//! crate for the same reason: both `script` and `net` need these types,
//! and `net` cannot depend on `script`.

use serde::{Deserialize, Serialize};
use servo_base::generic_channel::GenericCallback;
use servo_url::ImmutableOrigin;

/// A COS hash, per
/// <https://wicg.github.io/cross-origin-storage/#cos-hash>.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CosHash {
    pub algorithm: String,
    pub value: String,
}

/// The result of validating a [`CosHash`]'s shape, per
/// <https://wicg.github.io/cross-origin-storage/#validate-a-cos-request>
/// steps 1-2.
#[derive(Debug, PartialEq, Eq)]
pub enum CosHashValidationError {
    /// Step 1: `algorithm` is not a hash algorithm name recognized by
    /// [WEBCRYPTO].
    UnrecognizedAlgorithm,
    /// Step 2: `value` does not match the expected digest-length regex for
    /// `algorithm`.
    MalformedValue,
}

/// Hash algorithm names recognized by [WEBCRYPTO], paired with their
/// expected lowercase-hex digest length in characters -- twice the digest
/// length in bytes: SHA-1 is 160 bits/20 bytes, SHA-256 is 256 bits/32
/// bytes, SHA-384 is 384 bits/48 bytes, SHA-512 is 512 bits/64 bytes.
///
/// <https://w3c.github.io/webcrypto/#algorithm-overview>
const RECOGNIZED_HASH_ALGORITHMS: &[(&str, usize)] =
    &[("SHA-1", 40), ("SHA-256", 64), ("SHA-384", 96), ("SHA-512", 128)];

impl CosHash {
    /// A normalized `(algorithm, value)` key suitable for registry
    /// lookups: per
    /// <https://wicg.github.io/cross-origin-storage/#cos-hash-equal>, two
    /// COS hashes are equal when `algorithm` matches ASCII
    /// case-insensitively and `value` matches exactly.
    pub fn normalized_key(&self) -> (String, String) {
        (self.algorithm.to_ascii_uppercase(), self.value.clone())
    }

    /// <https://wicg.github.io/cross-origin-storage/#validate-a-cos-request>
    /// steps 1-2 (the hash-shape checks only; the `origins` option checks
    /// in step 3 are implemented at the call site in
    /// `script::dom::crossoriginstorage::crossoriginstoragemanager`,
    /// since they need script-side union-type handling this crate has no
    /// reason to depend on).
    ///
    /// Step 2's digest-length-regex check applies to `value` for *every*
    /// recognized algorithm, not only SHA-256: `value` is used verbatim
    /// (via `registry_key()`/`sanitized_entry_key()`) as part of an
    /// on-disk file path in `net::cross_origin_storage_thread`, so an
    /// unvalidated `value` for a non-SHA-256 algorithm would let a page
    /// supply arbitrary path components (e.g. `../../etc/whatever`) that
    /// end up read from or written to outside the intended directory.
    pub fn validate(&self) -> Result<(), CosHashValidationError> {
        let Some(&(_, expected_len)) = RECOGNIZED_HASH_ALGORITHMS
            .iter()
            .find(|(name, _)| self.algorithm.eq_ignore_ascii_case(name))
        else {
            return Err(CosHashValidationError::UnrecognizedAlgorithm);
        };

        let value_is_valid_hex = self.value.len() == expected_len &&
            self.value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !value_is_valid_hex {
            return Err(CosHashValidationError::MalformedValue);
        }

        Ok(())
    }
}

/// The `origins` value *requested* via `options.origins` on a create call.
/// `None` (at the call site, not represented here) means the option was
/// omitted entirely; see
/// <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum RequestedOrigins {
    Wildcard,
    List(Vec<ImmutableOrigin>),
}

/// The `origins` option's implementation-defined maximum list length,
/// per <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>:
/// "A list of origin strings has an implementation-defined maximum
/// length, so it can't be used as an undeclared substitute for `'*'`."
///
/// One shared constant for two different checks, matching the spec's
/// own singular framing ("an implementation-defined maximum length", not
/// two separate ones):
/// - `script::dom::crossoriginstorage::crossoriginstoragemanager::RequestFileHandle`
///   rejects a single call's own `options.origins` with a `TypeError`
///   if it exceeds this on its own, before any write is attempted, per
///   "If `origins` is a list longer than [this], the user agent must
///   throw a `TypeError` before attempting any write."
/// - `net::cross_origin_storage_thread::upgrade_resource_visibility`
///   instead silently drops the least-recently-used excess origins when
///   *merging* a new call's candidates into an already-list-scoped entry
///   would exceed this, per "Merging `origins` into an existing
///   list-scoped entry would exceed the implementation-defined maximum
///   length [results in] Success (excess origins silently dropped)".
///   This can legitimately happen without any single caller doing
///   anything wrong: independent, unrelated origins can each write the
///   same byte-identical resource with their own small `origins` list
///   (e.g. a shared open-source asset), and those lists merge over time.
///
/// 100 is this implementation's choice (the spec gives no number):
/// generous enough that no single realistic declaration, or a few
/// rounds of organic multi-writer merge growth, would plausibly hit it,
/// while remaining far too small to function as a practical `'*'`
/// substitute (that would take dozens of *separate* legitimate write
/// events, each contributing genuinely new origins).
pub const MAX_ORIGINS_LIST_LENGTH: usize = 100;

/// The result of `complete a read request`
/// (<https://wicg.github.io/cross-origin-storage/#complete-a-read-request>),
/// sent back over IPC.
#[derive(Debug, Deserialize, Serialize)]
pub enum CosReadOutcome {
    Found { bytes: Vec<u8>, type_string: String },
    NotFound,
    /// The entry exists but a write is (notionally) still in progress.
    PendingWrite,
}

/// The result of `verify and store`
/// (<https://wicg.github.io/cross-origin-storage/#verify-and-store>), sent
/// back over IPC. See `net::cross_origin_storage_thread`'s doc comment for
/// what enforces `RateLimited`/`QuotaExceeded` and why (this
/// implementation's own additions, not spec-mandated).
#[derive(Debug, Deserialize, Serialize)]
pub enum VerifyAndStoreOutcome {
    Success,
    /// Step 2 of `verify and store`: the computed digest did not match
    /// the requested hash. Also used if the request could not be
    /// sent/answered at all (this does not currently distinguish
    /// "verification failed" from "could not verify").
    HashMismatch,
    /// This implementation's per-origin write-probe rate limit was
    /// exceeded.
    RateLimited,
    /// This implementation's storage budget (global or per-origin) could
    /// not accommodate this write, even after evicting every entry it was
    /// allowed to evict to make room.
    QuotaExceeded { quota_bytes: u64, requested_bytes: u64 },
}

/// Messages understood by the Cross-Origin Storage service living in the
/// resource thread. Reached via
/// `CoreResourceMsg::ToCrossOriginStorage`, mirroring
/// `CoreResourceMsg::ToFileManager(FileManagerThreadMsg)`.
#[derive(Debug, Deserialize, Serialize)]
pub enum CosThreadMsg {
    /// `complete a read request`. Answered via a `GenericCallback` so the
    /// calling script thread never blocks on the response; see
    /// `script::dom::crossoriginstorage::registry`'s doc comment for why
    /// that matters.
    Read(CosHash, ImmutableOrigin, GenericCallback<CosReadOutcome>),
    /// `complete a create request` (registry half only). Carries the
    /// requesting origin so the resource thread can rate-limit it (see
    /// `net::cross_origin_storage_thread`'s doc comment on
    /// `consume_write_token`); no response is expected either way.
    Create(CosHash, ImmutableOrigin, Option<RequestedOrigins>),
    /// Sent when a write started via a `create: true` request is
    /// abandoned (the `FileSystemWritableFileStream`'s `abort()` was
    /// called) without ever reaching `close()`. Lets the registry remove
    /// the `Pending` entry immediately rather than leaving it stuck until
    /// a later request for the same hash notices it is stale; see
    /// `CrossOriginStorageStore::abandon_pending_write`.
    AbandonPendingWrite(CosHash),
    /// `verify and store`. Same `GenericCallback` reasoning as `Read`
    /// above.
    VerifyAndStore(
        CosHash,
        Vec<u8>,
        String,
        ImmutableOrigin,
        Option<RequestedOrigins>,
        GenericCallback<VerifyAndStoreOutcome>,
    ),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sha256_hash_is_accepted() {
        let h = CosHash {
            algorithm: "SHA-256".to_owned(),
            value: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa0".to_owned(),
        };
        assert_eq!(h.validate(), Ok(()));
    }

    #[test]
    fn algorithm_name_is_ascii_case_insensitive() {
        let h = CosHash {
            algorithm: "sha-256".to_owned(),
            value: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa0".to_owned(),
        };
        assert_eq!(h.validate(), Ok(()));
    }

    #[test]
    fn unrecognized_algorithm_is_rejected() {
        let h = CosHash {
            algorithm: "MD5".to_owned(),
            value: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa0".to_owned(),
        };
        assert_eq!(
            h.validate(),
            Err(CosHashValidationError::UnrecognizedAlgorithm)
        );
    }

    #[test]
    fn wrong_length_value_is_rejected() {
        let h = CosHash {
            algorithm: "SHA-256".to_owned(),
            value: "8f43".to_owned(),
        };
        assert_eq!(h.validate(), Err(CosHashValidationError::MalformedValue));
    }

    #[test]
    fn uppercase_hex_value_is_rejected() {
        let h = CosHash {
            algorithm: "SHA-256".to_owned(),
            value: "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA0".to_owned(),
        };
        assert_eq!(h.validate(), Err(CosHashValidationError::MalformedValue));
    }

    #[test]
    fn valid_sha1_sha384_and_sha512_hashes_are_accepted_at_their_own_lengths() {
        let sha1 = CosHash {
            algorithm: "SHA-1".to_owned(),
            value: "a".repeat(40),
        };
        assert_eq!(sha1.validate(), Ok(()));

        let sha384 = CosHash {
            algorithm: "SHA-384".to_owned(),
            value: "a".repeat(96),
        };
        assert_eq!(sha384.validate(), Ok(()));

        let sha512 = CosHash {
            algorithm: "SHA-512".to_owned(),
            value: "a".repeat(128),
        };
        assert_eq!(sha512.validate(), Ok(()));
    }

    #[test]
    fn wrong_length_value_is_rejected_for_non_sha256_algorithms_too() {
        // Regression test: `value` used to go completely unvalidated for
        // every algorithm except SHA-256, so a `SHA-1`/`SHA-384`/`SHA-512`
        // hash with an arbitrary `value` (of the wrong length, or not hex
        // at all) would pass validation.
        let sha1_wrong_length = CosHash {
            algorithm: "SHA-1".to_owned(),
            value: "a".repeat(64), // SHA-256's length, not SHA-1's.
        };
        assert_eq!(
            sha1_wrong_length.validate(),
            Err(CosHashValidationError::MalformedValue)
        );

        let sha384_not_hex = CosHash {
            algorithm: "SHA-384".to_owned(),
            value: "z".repeat(96),
        };
        assert_eq!(
            sha384_not_hex.validate(),
            Err(CosHashValidationError::MalformedValue)
        );
    }

    #[test]
    fn path_traversal_value_is_rejected_for_a_non_sha256_algorithm() {
        // `value` is used verbatim as part of an on-disk file path (see
        // `validate`'s doc comment); a `SHA-1` hash whose `value` was
        // never validated at all used to let this through unchanged.
        let h = CosHash {
            algorithm: "SHA-1".to_owned(),
            value: "../../../../etc/whatever".to_owned(),
        };
        assert_eq!(h.validate(), Err(CosHashValidationError::MalformedValue));
    }
}
