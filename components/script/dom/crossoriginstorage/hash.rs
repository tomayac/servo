/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Validation of a *COS hash*, per
//! <https://wicg.github.io/cross-origin-storage/#hashes> and the
//! `algorithm`/`value` checks in
//! <https://wicg.github.io/cross-origin-storage/#validate-a-cos-request>.
//!
//! This module is deliberately independent of the WebIDL-generated
//! `CrossOriginStorageRequestFileHandleHash` dictionary so that the
//! algorithm can be implemented, and unit tested, ahead of
//! `requestFileHandle()` itself landing (which additionally needs a
//! COS-scoped `FileSystemFileHandle`; see crossoriginstoragemanager.rs).

use regex::Regex;
use std::sync::LazyLock;

/// Hash algorithm names recognized by [WEBCRYPTO], mirrored here rather than
/// imported from `dom::webcrypto::subtlecrypto`'s private `CryptoAlgorithm`
/// enum, to keep this module's dependencies minimal while the two pieces of
/// code are unwired. A follow-up should consider sharing a single
/// public list instead of maintaining two.
///
/// <https://w3c.github.io/webcrypto/#algorithm-overview>
const RECOGNIZED_HASH_ALGORITHMS: &[&str] = &["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

/// <https://wicg.github.io/cross-origin-storage/#validate-a-cos-request>
/// step 2: for SHA-256, `value` must match `/^[0-9a-f]{64}$/`.
///
/// Other recognized algorithms are not normatively constrained by the
/// spec's own text ("this specification only normatively constrains
/// SHA-256"), so this module only spec-checks the SHA-256 case, and treats
/// other recognized algorithm names as syntactically unconstrained for now.
static SHA_256_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("static regex is valid"));

/// A COS hash, per <https://wicg.github.io/cross-origin-storage/#cos-hash>.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CosHash {
    pub(crate) algorithm: String,
    pub(crate) value: String,
}

/// The result of `validate a COS request`'s hash-related steps: either the
/// hash was well-formed, or a reason it was not (to be surfaced as a
/// `TypeError` by the caller once this is wired into `requestFileHandle()`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HashValidationError {
    /// Step 1: `algorithm` is not a hash algorithm name recognized by
    /// [WEBCRYPTO].
    UnrecognizedAlgorithm,
    /// Step 2: `value` does not match the expected digest-length regex for
    /// `algorithm`.
    MalformedValue,
}

impl CosHash {
    /// <https://wicg.github.io/cross-origin-storage/#validate-a-cos-request>
    /// steps 1-2 (the hash-shape checks only; the `origins` option checks
    /// in step 3 belong to a future `CrossOriginStorageRequestFileHandleOptions`
    /// validator once `requestFileHandle()` itself is wired up).
    pub(crate) fn validate(&self) -> Result<(), HashValidationError> {
        // Step 1. If hash["algorithm"] is not a hash algorithm name
        // recognized by [WEBCRYPTO], return a new TypeError.
        let is_sha256 = self.algorithm.eq_ignore_ascii_case("SHA-256");
        let is_recognized = RECOGNIZED_HASH_ALGORITHMS
            .iter()
            .any(|name| self.algorithm.eq_ignore_ascii_case(name));
        if !is_recognized {
            return Err(HashValidationError::UnrecognizedAlgorithm);
        }

        // Step 2. If hash["value"] does not match /^[0-9a-f]{64}$/ when
        // hash["algorithm"] is an ASCII case-insensitive match for
        // "SHA-256", return a new TypeError.
        if is_sha256 && !SHA_256_VALUE_RE.is_match(&self.value) {
            return Err(HashValidationError::MalformedValue);
        }

        Ok(())
    }
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
    fn valid_sha256_hash_is_accepted() {
        let h = hash(
            "SHA-256",
            "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa",
        );
        assert_eq!(h.validate(), Ok(()));
    }

    #[test]
    fn algorithm_name_is_ascii_case_insensitive() {
        let h = hash(
            "sha-256",
            "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa",
        );
        assert_eq!(h.validate(), Ok(()));
    }

    #[test]
    fn unrecognized_algorithm_is_rejected() {
        let h = hash(
            "MD5",
            "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa",
        );
        assert_eq!(h.validate(), Err(HashValidationError::UnrecognizedAlgorithm));
    }

    #[test]
    fn wrong_length_value_is_rejected() {
        let h = hash("SHA-256", "8f43");
        assert_eq!(h.validate(), Err(HashValidationError::MalformedValue));
    }

    #[test]
    fn uppercase_hex_value_is_rejected() {
        // Per spec, `value` is normatively lowercase; the regex enforces
        // this directly rather than through a separate case-folding step.
        let h = hash(
            "SHA-256",
            "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA",
        );
        assert_eq!(h.validate(), Err(HashValidationError::MalformedValue));
    }

    #[test]
    fn non_hex_characters_are_rejected() {
        let h = hash(
            "SHA-256",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        );
        assert_eq!(h.validate(), Err(HashValidationError::MalformedValue));
    }

    #[test]
    fn sha1_value_shape_is_unconstrained_by_this_module() {
        // The spec only normatively constrains SHA-256's value shape; other
        // recognized algorithms (SHA-1 here) are accepted regardless of
        // value shape at this layer.
        let h = hash("SHA-1", "not-a-real-digest");
        assert_eq!(h.validate(), Ok(()));
    }
}
