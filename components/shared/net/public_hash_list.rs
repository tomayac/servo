/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Loader for Cross-Origin Storage's Public Hash List (PHL)
//! (<https://wicg.github.io/cross-origin-storage/#phl>): a k-anonymity
//! allowlist of SHA-256 digests unconditionally eligible for cross-origin
//! availability disclosure, with "governance by the WHATWG, modeled
//! directly on the Public Suffix List's cross-vendor, rolling-release
//! precedent" -- see [`crate::pub_domains`] for that precedent within
//! this codebase.
//!
//! The bundled snapshot comes from
//! <https://github.com/WICG/cross-origin-storage/tree/main/public-hash-list/implementation>,
//! generated and published directly in the spec repo itself, and tracked
//! there via Git LFS (see `update_public_hash_list` in
//! `python/servo/bootstrap_commands.py` for why that means fetching it
//! isn't as simple as a plain `raw.githubusercontent.com` URL); refresh it
//! with `./mach update-public-hash-list` (also run automatically on a
//! weekly schedule -- see `.github/workflows/update-public-hash-list.yml`
//! -- since, per the spec text above, this is meant to be a rolling
//! release, not a one-time snapshot). The list is bundled as sorted,
//! packed 32-byte SHA-256 digests with no delimiters
//! (`components/default-resources/resources/public_hash_list.bin`)
//! rather than the upstream `.dat` file's hex-with-comments text format,
//! purely to keep the compiled-in resource compact; sortedness enables
//! `binary_search` for O(log n) lookups instead of a `HashSet` (a
//! `HashSet<[u8; 32]>` of ~300k entries would cost meaningfully more
//! memory for the same guarantee here, and this list is read-only after
//! load).

use std::sync::LazyLock;

use embedder_traits::resources::{self, Resource};

static PUBLIC_HASH_LIST: LazyLock<Vec<[u8; 32]>> = LazyLock::new(load_public_hash_list);

fn load_public_hash_list() -> Vec<[u8; 32]> {
    let bytes = resources::read_bytes(Resource::PublicHashList);
    let mut digests: Vec<[u8; 32]> = bytes
        .chunks_exact(32)
        .map(|chunk| {
            chunk
                .try_into()
                .expect("chunks_exact(32) always yields a 32-byte slice")
        })
        .collect();
    // Sorted defensively at load time rather than trusting the bundled
    // file to already be sorted, so `binary_search` below is always
    // correct even if the update mechanism's own sort step ever changes.
    digests.sort_unstable();
    digests
}

/// Whether `digest` (a raw SHA-256 digest) is present on the bundled
/// Public Hash List snapshot.
pub fn is_on_public_hash_list(digest: &[u8; 32]) -> bool {
    PUBLIC_HASH_LIST.binary_search(digest).is_ok()
}

/// Convenience wrapper for a lowercase-hex SHA-256 digest string (a COS
/// hash's `value`, already validated to this exact shape by
/// `CosHash::validate` for callers going through that path). Returns
/// `false` for malformed input instead of panicking, since a caller
/// should not need to pre-validate before asking this question.
pub fn is_hex_digest_on_public_hash_list(hex_value: &str) -> bool {
    match hex_to_digest(hex_value) {
        Some(digest) => is_on_public_hash_list(&digest),
        None => false,
    }
}

fn hex_to_digest(hex_value: &str) -> Option<[u8; 32]> {
    if hex_value.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex_value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}
