/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Thin IPC client for the Cross-Origin Storage registry, which now
//! actually lives in the resource thread
//! (`net::cross_origin_storage_thread::CrossOriginStorageStore`), reached
//! via `CoreResourceMsg::ToCrossOriginStorage`. This replaces the earlier
//! `thread_local!`-based version: same function signatures
//! (`complete_a_read_request`, `complete_a_create_request`,
//! `verify_and_store`), same `ReadOutcome`/`EntryBytes` shapes used by
//! callers, but each function now sends a message and blocks on the
//! response instead of touching in-process state directly -- mirroring
//! `document.cookie`'s `GetCookieStringForUrl` pattern in
//! `dom/document/document.rs` (construct a channel via
//! `servo_base::generic_channel::channel()`, send via
//! `global.resource_threads().send(...)`, block on `rx.recv()`).
//!
//! `RequestedOrigins`, `CosReadOutcome` (the wire form) and the actual
//! spec algorithms now live in `net_traits::cross_origin_storage_thread`
//! / `net::cross_origin_storage_thread`; see those modules' doc comments
//! for what is and is not spec-conformant. Nothing about that changed in
//! this file -- only where the algorithms run.
//!
//! Blocking the calling script thread on each of these calls is a real,
//! deliberate simplification, not an oversight: it keeps every call site
//! that was already written against the previous, synchronous
//! `thread_local!` version unchanged (only a `global: &GlobalScope`
//! parameter was added), rather than requiring every caller to be
//! rewritten to defer Promise resolution via a response-handler pattern.
//! `document.cookie`'s getter does the same blocking-IPC-from-script
//! thing for the same reason. A future revision could convert these to
//! non-blocking (queue a global task on response, matching e.g.
//! `globalscope.rs`'s `FileListener`/`read_file_async`) without changing
//! any caller's signature.

pub(crate) use net_traits::cross_origin_storage_thread::RequestedOrigins;

use net_traits::CoreResourceMsg;
use net_traits::cross_origin_storage_thread::{CosReadOutcome, CosThreadMsg};
use servo_base::generic_channel::{self, GenericSend};
use servo_url::ImmutableOrigin;

use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::globalscope::GlobalScope;

/// A written [COS entry](https://wicg.github.io/cross-origin-storage/#cos-entry)'s
/// bytes, as received over IPC from the resource thread.
pub(crate) struct EntryBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) type_string: String,
}

/// The outcome of `complete a read request`
/// (<https://wicg.github.io/cross-origin-storage/#complete-a-read-request>).
pub(crate) enum ReadOutcome {
    Found(EntryBytes),
    NotFound,
    /// The entry exists but a write is (notionally) still in progress.
    PendingWrite,
}

impl From<CosReadOutcome> for ReadOutcome {
    fn from(outcome: CosReadOutcome) -> Self {
        match outcome {
            CosReadOutcome::Found { bytes, type_string } => {
                ReadOutcome::Found(EntryBytes { bytes, type_string })
            },
            CosReadOutcome::NotFound => ReadOutcome::NotFound,
            CosReadOutcome::PendingWrite => ReadOutcome::PendingWrite,
        }
    }
}

/// <https://wicg.github.io/cross-origin-storage/#complete-a-read-request>
pub(crate) fn complete_a_read_request(
    global: &GlobalScope,
    hash: &CosHash,
    origin: &ImmutableOrigin,
) -> ReadOutcome {
    let Some((response_sender, response_receiver)) = generic_channel::channel() else {
        // Channel construction failing is not something a caller can
        // meaningfully recover from; treat as "not found" (fall back to
        // network), the same fallback the spec already prescribes for
        // every other reason a read can fail to disclose an entry.
        return ReadOutcome::NotFound;
    };

    let sent = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::Read(
            hash.clone(),
            origin.clone(),
            response_sender,
        ),
    ));
    if sent.is_err() {
        return ReadOutcome::NotFound;
    }

    match response_receiver.recv() {
        Ok(outcome) => outcome.into(),
        Err(_) => ReadOutcome::NotFound,
    }
}

/// <https://wicg.github.io/cross-origin-storage/#complete-a-create-request>
/// (registry half only; handle construction is the caller's job). No
/// response is expected, matching the previous version's signature.
pub(crate) fn complete_a_create_request(
    global: &GlobalScope,
    hash: &CosHash,
    requested_origins: Option<RequestedOrigins>,
) {
    let _ = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::Create(
            hash.clone(),
            requested_origins,
        ),
    ));
}

/// <https://wicg.github.io/cross-origin-storage/#verify-and-store>
///
/// Returns `Err(())` on hash mismatch (the caller should reject with
/// `DataError`, per spec), or if the request could not be sent/answered at
/// all (treated the same way, since neither this function's signature nor
/// its callers currently distinguish "verification failed" from
/// "could not verify").
pub(crate) fn verify_and_store(
    global: &GlobalScope,
    hash: &CosHash,
    bytes: Vec<u8>,
    type_string: String,
    origin: ImmutableOrigin,
    requested_origins: Option<RequestedOrigins>,
) -> Result<(), ()> {
    let Some((response_sender, response_receiver)) = generic_channel::channel() else {
        return Err(());
    };

    let sent = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::VerifyAndStore(
            hash.clone(),
            bytes,
            type_string,
            origin,
            requested_origins,
            response_sender,
        ),
    ));
    if sent.is_err() {
        return Err(());
    }

    response_receiver.recv().unwrap_or(Err(()))
}
