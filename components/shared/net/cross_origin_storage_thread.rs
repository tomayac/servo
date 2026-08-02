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

use ipc_channel::ipc::IpcSender;
use serde::{Deserialize, Serialize};
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

/// Hash algorithm names recognized by [WEBCRYPTO].
///
/// <https://w3c.github.io/webcrypto/#algorithm-overview>
const RECOGNIZED_HASH_ALGORITHMS: &[&str] = &["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

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
    pub fn validate(&self) -> Result<(), CosHashValidationError> {
        let is_sha256 = self.algorithm.eq_ignore_ascii_case("SHA-256");
        let is_recognized = RECOGNIZED_HASH_ALGORITHMS
            .iter()
            .any(|name| self.algorithm.eq_ignore_ascii_case(name));
        if !is_recognized {
            return Err(CosHashValidationError::UnrecognizedAlgorithm);
        }

        if is_sha256 {
            let value_is_64_lowercase_hex = self.value.len() == 64 &&
                self.value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !value_is_64_lowercase_hex {
                return Err(CosHashValidationError::MalformedValue);
            }
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

/// Messages understood by the Cross-Origin Storage service living in the
/// resource thread. Reached via
/// `CoreResourceMsg::ToCrossOriginStorage`, mirroring
/// `CoreResourceMsg::ToFileManager(FileManagerThreadMsg)`.
#[derive(Debug, Deserialize, Serialize)]
pub enum CosThreadMsg {
    /// `complete a read request`.
    Read(CosHash, ImmutableOrigin, IpcSender<CosReadOutcome>),
    /// `complete a create request` (registry half only).
    Create(CosHash, Option<RequestedOrigins>),
    /// `verify and store`. The response is `Ok(())` on success, `Err(())`
    /// on hash mismatch (caller should reject with `DataError`).
    VerifyAndStore(
        CosHash,
        Vec<u8>,
        String,
        ImmutableOrigin,
        Option<RequestedOrigins>,
        IpcSender<Result<(), ()>>,
    ),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sha256_hash_is_accepted() {
        let h = CosHash {
            algorithm: "SHA-256".to_owned(),
            value: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa".to_owned(),
        };
        assert_eq!(h.validate(), Ok(()));
    }

    #[test]
    fn algorithm_name_is_ascii_case_insensitive() {
        let h = CosHash {
            algorithm: "sha-256".to_owned(),
            value: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa".to_owned(),
        };
        assert_eq!(h.validate(), Ok(()));
    }

    #[test]
    fn unrecognized_algorithm_is_rejected() {
        let h = CosHash {
            algorithm: "MD5".to_owned(),
            value: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa".to_owned(),
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
            value: "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA".to_owned(),
        };
        assert_eq!(h.validate(), Err(CosHashValidationError::MalformedValue));
    }
}
