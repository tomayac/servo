/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use net_traits::public_hash_list::is_hex_digest_on_public_hash_list;
use servo_default_resources as _;

// These rely on a real digest already present in the bundled snapshot;
// this test may need to be updated if that digest is ever removed by a
// future `./mach update-public-hash-list` refresh.
const KNOWN_DIGEST: &str = "00003bcf96fc9cb1ac3c88678137b49a3a67a7991aa46f8c944fb8756b51b84e";

#[test]
fn a_known_digest_from_the_bundled_snapshot_is_on_the_list() {
    assert!(is_hex_digest_on_public_hash_list(KNOWN_DIGEST));
}

#[test]
fn an_all_zero_digest_is_not_on_the_list() {
    assert!(!is_hex_digest_on_public_hash_list(&"0".repeat(64)));
}

#[test]
fn uppercase_hex_still_matches_the_same_underlying_digest() {
    // Membership is about the digest's *bytes*, not the string's casing
    // -- `u8::from_str_radix` parses either case the same way, so an
    // uppercase-hex spelling of a listed digest still matches. In
    // practice this never comes up for real COS hashes: `CosHash::validate`
    // already rejects uppercase `value`s before this function is ever
    // called from `cross_origin_storage_thread.rs`.
    assert!(is_hex_digest_on_public_hash_list(
        &KNOWN_DIGEST.to_ascii_uppercase()
    ));
}

#[test]
fn malformed_input_is_not_on_the_list_rather_than_panicking() {
    assert!(!is_hex_digest_on_public_hash_list(""));
    assert!(!is_hex_digest_on_public_hash_list("not-hex-at-all"));
    assert!(!is_hex_digest_on_public_hash_list(&"a".repeat(63)));
    assert!(!is_hex_digest_on_public_hash_list(&"a".repeat(65)));
}
