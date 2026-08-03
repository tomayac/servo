/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Thin IPC client for the Cross-Origin Storage registry, which actually
//! lives in the resource thread
//! (`net::cross_origin_storage_thread::CrossOriginStorageStore`), reached
//! via `CoreResourceMsg::ToCrossOriginStorage`.
//!
//! `RequestedOrigins`, `CosReadOutcome` (the wire form) and the actual
//! spec algorithms live in `net_traits::cross_origin_storage_thread` /
//! `net::cross_origin_storage_thread`; see those modules' doc comments
//! for what is and is not spec-conformant. Nothing about that changed in
//! this file -- only how the response gets back to script.
//!
//! Non-blocking: each function here sends a message carrying a
//! `GenericCallback` and returns immediately; the resource thread's
//! response invokes that callback (on the resource thread, or the IPC
//! router thread in multiprocess mode -- never the calling script
//! thread), whose only job is to queue a task back onto the *correct*
//! script thread to actually resolve/reject the promise. This mirrors
//! `StorageManager`'s `persisted()`/`persist()`/`estimate()` in
//! `dom/storage/storagemanager.rs` (`GenericCallback` + a response-handler
//! struct holding a `TrustedPromise` + `SendableTaskSource`,
//! `handler.handle()` queuing a `task!` that roots the promise and
//! resolves/rejects it).
//!
//! This matters because a Worker has only one script thread: blocking it
//! for the duration of an IPC round-trip (which, for `verify_and_store`,
//! includes writing the written bytes to disk) freezes that worker
//! entirely, with nothing else able to run concurrently. On a Window, the
//! same kind of block also freezes scroll input handling, since Servo's
//! desktop port dispatches wheel events through a synchronous,
//! cancelable-by-script `wheel` DOM event with no timeout fallback: any
//! long blocking script-thread call freezes scrolling along with it.

use std::rc::Rc;
use std::time::SystemTime;

pub(crate) use net_traits::cross_origin_storage_thread::{MAX_ORIGINS_LIST_LENGTH, RequestedOrigins};

use net_traits::CoreResourceMsg;
use net_traits::cross_origin_storage_thread::{CosReadOutcome, CosThreadMsg, VerifyAndStoreOutcome};
use servo_base::generic_channel::{self, GenericSend};
use servo_constellation_traits::BlobImpl;
use servo_url::ImmutableOrigin;

use crate::dom::bindings::error::Error;
use crate::dom::bindings::num::Finite;
use crate::dom::bindings::refcounted::TrustedPromise;
use crate::dom::bindings::str::{DOMString, USVString};
use crate::dom::crossoriginstorage::filesystemfilehandle::FileSystemFileHandle;
use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::file::File;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;
use crate::task_source::SendableTaskSource;

/// A written [COS entry](https://wicg.github.io/cross-origin-storage/#cos-entry)'s
/// bytes, as received over IPC from the resource thread.
pub(crate) struct EntryBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) type_string: String,
}

/// The outcome of `complete a read request`
/// (<https://wicg.github.io/cross-origin-storage/#complete-a-read-request>).
enum ReadOutcome {
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

/// Resolves/rejects a `requestFileHandle()` (read path) promise once the
/// resource thread responds. Runs on whatever thread invokes the
/// `GenericCallback` (not necessarily, and in practice never, the script
/// thread that created it), so its only job is queuing a task back onto
/// that script thread -- see this module's doc comment.
struct CosReadResponseHandler {
    trusted_promise: Option<TrustedPromise>,
    task_source: SendableTaskSource,
    name: USVString,
}

impl CosReadResponseHandler {
    fn new(trusted_promise: TrustedPromise, task_source: SendableTaskSource, name: USVString) -> Self {
        Self {
            trusted_promise: Some(trusted_promise),
            task_source,
            name,
        }
    }

    fn handle(&mut self, outcome: ReadOutcome) {
        let Some(trusted_promise) = self.trusted_promise.take() else {
            error!("Cross-Origin Storage read response handler called twice.");
            return;
        };
        let name = self.name.clone();
        self.task_source
            .queue(task!(cos_read_response: move |cx| {
                let promise = trusted_promise.root();
                let mut realm = js::realm::CurrentRealm::assert(cx);
                let global = GlobalScope::from_current_realm(&mut realm);
                match outcome {
                    ReadOutcome::Found(entry) => {
                        let handle = FileSystemFileHandle::new_for_read(cx, &global, name, entry);
                        promise.resolve_native(cx, &handle);
                    },
                    ReadOutcome::NotFound => promise.reject_error(cx, Error::NotFound(None)),
                    ReadOutcome::PendingWrite => promise.reject_error(cx, Error::NotAllowed(None)),
                }
            }));
    }
}

/// <https://wicg.github.io/cross-origin-storage/#complete-a-read-request>
///
/// Resolves/rejects `promise` asynchronously (see this module's doc
/// comment); does not return a value.
pub(crate) fn complete_a_read_request(
    global: &GlobalScope,
    hash: &CosHash,
    origin: &ImmutableOrigin,
    promise: &Rc<Promise>,
    task_source: SendableTaskSource,
    name: USVString,
) {
    let mut handler = CosReadResponseHandler::new(TrustedPromise::new(promise.clone()), task_source, name);
    let callback = generic_channel::GenericCallback::new(move |message| {
        let outcome = message.map(Into::into).unwrap_or(ReadOutcome::NotFound);
        handler.handle(outcome);
    })
    .expect("Could not create Cross-Origin Storage read callback");

    let sent = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::Read(hash.clone(), origin.clone(), callback.clone()),
    ));
    if sent.is_err() &&
        let Err(error) = callback.send(CosReadOutcome::NotFound)
    {
        error!("Failed to deliver Cross-Origin Storage read response: {error}");
    }
}

/// Resolves/rejects a `getFile()` (called on a create-backed handle)
/// promise once the resource thread responds. Same shape as
/// `CosReadResponseHandler`, but resolves with a `File` directly instead
/// of constructing a new `FileSystemFileHandle` -- see
/// `complete_a_read_request_for_file`.
struct CosReadForFileResponseHandler {
    trusted_promise: Option<TrustedPromise>,
    task_source: SendableTaskSource,
    name: USVString,
}

impl CosReadForFileResponseHandler {
    fn new(trusted_promise: TrustedPromise, task_source: SendableTaskSource, name: USVString) -> Self {
        Self {
            trusted_promise: Some(trusted_promise),
            task_source,
            name,
        }
    }

    fn handle(&mut self, outcome: ReadOutcome) {
        let Some(trusted_promise) = self.trusted_promise.take() else {
            error!("Cross-Origin Storage read-for-file response handler called twice.");
            return;
        };
        let name = self.name.clone();
        self.task_source
            .queue(task!(cos_read_for_file_response: move |cx| {
                let promise = trusted_promise.root();
                let mut realm = js::realm::CurrentRealm::assert(cx);
                let global = GlobalScope::from_current_realm(&mut realm);
                match outcome {
                    ReadOutcome::Found(entry) => {
                        let blob_impl = BlobImpl::new_from_bytes(entry.bytes, entry.type_string);
                        let file = File::new(
                            cx,
                            &global,
                            blob_impl,
                            DOMString::from(name.to_string()),
                            Some(SystemTime::now()),
                        );
                        promise.resolve_native(cx, &file);
                    },
                    ReadOutcome::NotFound => promise.reject_error(cx, Error::NotFound(None)),
                    ReadOutcome::PendingWrite => promise.reject_error(cx, Error::NotAllowed(None)),
                }
            }));
    }
}

/// Like `complete_a_read_request`, but resolves `promise` with a `File`
/// directly instead of constructing a new `FileSystemFileHandle`. Used by
/// `FileSystemFileHandle::GetFile()` on a create-backed handle: per spec,
/// `getFile()` works on any handle from a storing origin regardless of
/// how it was obtained, so a create-backed handle whose write has
/// completed is readable the same way a fresh read-backed handle's
/// `getFile()` would be. Reuses the exact same registry lookup
/// (`CosThreadMsg::Read`) rather than duplicating it, since a create-mode
/// handle already carries the same `hash`/`origin` a read-mode lookup
/// needs.
pub(crate) fn complete_a_read_request_for_file(
    global: &GlobalScope,
    hash: &CosHash,
    origin: &ImmutableOrigin,
    promise: &Rc<Promise>,
    task_source: SendableTaskSource,
    name: USVString,
) {
    let mut handler =
        CosReadForFileResponseHandler::new(TrustedPromise::new(promise.clone()), task_source, name);
    let callback = generic_channel::GenericCallback::new(move |message| {
        let outcome = message.map(Into::into).unwrap_or(ReadOutcome::NotFound);
        handler.handle(outcome);
    })
    .expect("Could not create Cross-Origin Storage read-for-file callback");

    let sent = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::Read(hash.clone(), origin.clone(), callback.clone()),
    ));
    if sent.is_err() &&
        let Err(error) = callback.send(CosReadOutcome::NotFound)
    {
        error!("Failed to deliver Cross-Origin Storage read-for-file response: {error}");
    }
}

/// <https://wicg.github.io/cross-origin-storage/#complete-a-create-request>
/// (registry half only; handle construction is the caller's job). No
/// response is expected (and was none before this file's functions
/// became non-blocking either): the resource thread never replies to
/// `CosThreadMsg::Create` at all.
pub(crate) fn complete_a_create_request(
    global: &GlobalScope,
    hash: &CosHash,
    origin: &ImmutableOrigin,
    requested_origins: Option<RequestedOrigins>,
) {
    let _ = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::Create(
            hash.clone(),
            origin.clone(),
            requested_origins,
        ),
    ));
}

/// Tells the registry a write started via a `create: true` request was
/// abandoned (`FileSystemWritableFileStream.abort()` was called), so its
/// `Pending` entry can be removed immediately; see
/// `net::cross_origin_storage_thread::CrossOriginStorageStore::abandon_pending_write`.
/// Fire-and-forget, like `complete_a_create_request`: there is nothing
/// meaningful to do in script if this message does not arrive (the
/// entry's own staleness timeout is the backstop for that).
pub(crate) fn abandon_pending_write(global: &GlobalScope, hash: &CosHash) {
    let _ = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::AbandonPendingWrite(hash.clone()),
    ));
}

/// Resolves/rejects a `close()` (write path) promise once the resource
/// thread responds to `verify_and_store`; see `CosReadResponseHandler`
/// (same shape, simpler payload).
struct CosVerifyAndStoreResponseHandler {
    trusted_promise: Option<TrustedPromise>,
    task_source: SendableTaskSource,
}

impl CosVerifyAndStoreResponseHandler {
    fn new(trusted_promise: TrustedPromise, task_source: SendableTaskSource) -> Self {
        Self {
            trusted_promise: Some(trusted_promise),
            task_source,
        }
    }

    fn handle(&mut self, outcome: VerifyAndStoreOutcome) {
        let Some(trusted_promise) = self.trusted_promise.take() else {
            error!("Cross-Origin Storage verify-and-store response handler called twice.");
            return;
        };
        self.task_source
            .queue(task!(cos_verify_and_store_response: move |cx| {
                let promise = trusted_promise.root();
                match outcome {
                    VerifyAndStoreOutcome::Success => promise.resolve_native(cx, &()),
                    // Step 2 of verify-and-store: reject with DataError on
                    // hash mismatch, leaving the entry unmodified (nothing
                    // to roll back: the registry is only ever mutated on
                    // the success path).
                    VerifyAndStoreOutcome::HashMismatch => promise.reject_error(cx, Error::Data(None)),
                    // This implementation's write-probe rate limit (see
                    // net::cross_origin_storage_thread's doc comment);
                    // not a spec-defined outcome.
                    VerifyAndStoreOutcome::RateLimited => promise.reject_error(cx, Error::NotAllowed(None)),
                    // This implementation's storage budget (see the same
                    // module's doc comment); not spec-defined either, but
                    // QuotaExceededError is the standard DOMException for
                    // exactly this kind of storage-limit situation.
                    VerifyAndStoreOutcome::QuotaExceeded { quota_bytes, requested_bytes } => {
                        promise.reject_error(cx, Error::QuotaExceeded {
                            quota: Some(Finite::wrap(quota_bytes as f64)),
                            requested: Some(Finite::wrap(requested_bytes as f64)),
                        });
                    },
                }
            }));
    }
}

/// <https://wicg.github.io/cross-origin-storage/#verify-and-store>
///
/// Resolves `promise` with `undefined` on success; rejects per
/// `VerifyAndStoreOutcome`'s doc comment (`DataError` on hash mismatch,
/// or if the request could not be sent/answered at all -- this does not
/// currently distinguish "verification failed" from "could not verify";
/// `NotAllowedError`/`QuotaExceededError` for this implementation's own
/// rate-limit/storage-budget additions).
pub(crate) fn verify_and_store(
    global: &GlobalScope,
    hash: &CosHash,
    bytes: Vec<u8>,
    type_string: String,
    origin: ImmutableOrigin,
    requested_origins: Option<RequestedOrigins>,
    promise: &Rc<Promise>,
    task_source: SendableTaskSource,
) {
    let mut handler = CosVerifyAndStoreResponseHandler::new(TrustedPromise::new(promise.clone()), task_source);
    let callback = generic_channel::GenericCallback::new(move |message| {
        let outcome = message.unwrap_or(VerifyAndStoreOutcome::HashMismatch);
        handler.handle(outcome);
    })
    .expect("Could not create Cross-Origin Storage verify-and-store callback");

    let sent = global.resource_threads().send(CoreResourceMsg::ToCrossOriginStorage(
        CosThreadMsg::VerifyAndStore(
            hash.clone(),
            bytes,
            type_string,
            origin,
            requested_origins,
            callback.clone(),
        ),
    ));
    if sent.is_err() &&
        let Err(error) = callback.send(VerifyAndStoreOutcome::HashMismatch)
    {
        error!("Failed to deliver Cross-Origin Storage verify-and-store response: {error}");
    }
}
