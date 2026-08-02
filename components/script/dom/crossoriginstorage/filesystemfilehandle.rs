/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://fs.spec.whatwg.org/#filesystemfilehandle>
//!
//! See `FileSystemFileHandle.webidl` for what is deliberately omitted
//! (`createSyncAccessHandle()`) and why.
//!
//! Per <https://wicg.github.io/cross-origin-storage/#cos-file-system>, every
//! handle obtained from Cross-Origin Storage is already fully authorized
//! before being returned to script, so neither `getFile()` nor
//! `createWritable()` here ever trigger a permission prompt -- there is no
//! permission-check machinery to call in the first place, which matches
//! the spec's intent rather than being an oversight.
//!
//! A handle is one of two shapes, matching the two ways
//! `CrossOriginStorageManager::RequestFileHandle` can produce one:
//! - `Backing::Read`: from a successful read (`options.create` unset or
//!   false). Carries the already-fetched entry bytes, so `getFile()`
//!   resolves from them directly with no further IPC.
//! - `Backing::Create`: from a create request (`options.create: true`).
//!   Carries the hash, requesting origin, and requested `origins` value
//!   needed both to call `registry::verify_and_store` when the resulting
//!   writable stream is closed, and (see `GetFile()` below) to do a fresh
//!   registry read lookup for the same hash if `getFile()` is called on
//!   this handle.
//!
//! `createWritable()` still only works on a `Backing::Create` handle, not
//! a `Backing::Read` one: the real spec allows `createWritable()` on any
//! handle whose caller has write rights, not just ones from a
//! `create: true` request, but supporting that would need a `Backing::Read`
//! handle to carry write-rights context (`requested_origins`) it does not
//! currently have, which is a real, if narrower, remaining gap.

use std::rc::Rc;
use std::time::SystemTime;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_constellation_traits::BlobImpl;
use servo_url::ImmutableOrigin;

use crate::dom::bindings::codegen::Bindings::FileSystemFileHandleBinding::{
    FileSystemCreateWritableOptions, FileSystemFileHandleMethods,
};
use crate::dom::bindings::codegen::Bindings::FileSystemHandleBinding::FileSystemHandleKind;
use crate::dom::bindings::error::Error;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::{DOMString, USVString};
use crate::dom::crossoriginstorage::filesystemhandle::FileSystemHandle;
use crate::dom::crossoriginstorage::filesystemwritablefilestream::FileSystemWritableFileStream;
use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::crossoriginstorage::registry::{self, EntryBytes, RequestedOrigins};
use crate::dom::file::File;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;

enum Backing {
    Read(EntryBytes),
    Create {
        hash: CosHash,
        origin: ImmutableOrigin,
        requested_origins: Option<RequestedOrigins>,
    },
}

#[dom_struct]
pub(crate) struct FileSystemFileHandle {
    file_system_handle: FileSystemHandle,
    #[no_trace]
    #[ignore_malloc_size_of = "Not yet measured"]
    backing: Backing,
}

impl FileSystemFileHandle {
    fn new_inherited(name: USVString, backing: Backing) -> FileSystemFileHandle {
        FileSystemFileHandle {
            file_system_handle: FileSystemHandle::new_inherited(FileSystemHandleKind::File, name),
            backing,
        }
    }

    /// Construct a handle for a COS entry already found in the registry
    /// (the `options.create` unset/false path).
    ///
    /// `name` is not part of a COS entry per the real spec (a
    /// `FileSystemFileHandle` from Cross-Origin Storage has no
    /// developer-meaningful name; entries are identified purely by hash),
    /// so callers currently pass the hash's `value` as a placeholder. A
    /// real registry implementation should revisit this once `name`'s
    /// actual role in `getFile()`'s resulting `File.name` is pinned down
    /// against the spec text.
    pub(crate) fn new_for_read(
        cx: &mut JSContext,
        global: &GlobalScope,
        name: USVString,
        entry: EntryBytes,
    ) -> DomRoot<FileSystemFileHandle> {
        reflect_dom_object_with_cx(
            Box::new(FileSystemFileHandle::new_inherited(
                name,
                Backing::Read(entry),
            )),
            global,
            cx,
        )
    }

    /// Construct a handle for a create request (`options.create: true`).
    /// See this module's doc comment for what `origin`/`requested_origins`
    /// are for.
    pub(crate) fn new_for_create(
        cx: &mut JSContext,
        global: &GlobalScope,
        name: USVString,
        hash: CosHash,
        origin: ImmutableOrigin,
        requested_origins: Option<RequestedOrigins>,
    ) -> DomRoot<FileSystemFileHandle> {
        reflect_dom_object_with_cx(
            Box::new(FileSystemFileHandle::new_inherited(
                name,
                Backing::Create {
                    hash,
                    origin,
                    requested_origins,
                },
            )),
            global,
            cx,
        )
    }
}

impl FileSystemFileHandleMethods<crate::DomTypeHolder> for FileSystemFileHandle {
    /// <https://fs.spec.whatwg.org/#dom-filesystemfilehandle-getfile>
    ///
    /// On a `Backing::Read` handle, this is simplified relative to the
    /// full File System Standard algorithm: that algorithm round-trips
    /// through an I/O task queue because a general handle can be backed
    /// by disk I/O with real latency and failure modes, but the bytes are
    /// already in hand here, so this resolves synchronously instead of
    /// queuing a task. On a `Backing::Create` handle there genuinely is
    /// an IPC round-trip (a fresh registry read lookup for this handle's
    /// hash), so that branch resolves/rejects asynchronously; see
    /// `registry::complete_a_read_request_for_file`.
    fn GetFile(&self, realm: &mut CurrentRealm) -> Rc<Promise> {
        let promise = Promise::new_in_realm(realm);

        match &self.backing {
            Backing::Read(entry) => {
                let blob_impl =
                    BlobImpl::new_from_bytes(entry.bytes.clone(), entry.type_string.clone());
                let name = DOMString::from(self.file_system_handle.name().to_string());
                let file = File::new(
                    realm,
                    &self.file_system_handle.global(),
                    blob_impl,
                    name,
                    Some(SystemTime::now()),
                );
                promise.resolve_native(realm, &file);
            },
            Backing::Create { hash, origin, .. } => {
                // Per spec, getFile() works on any handle from a storing
                // origin regardless of how it was obtained: a
                // create-backed handle whose write has already completed
                // (state Written) should read back the same as a fresh
                // read-backed handle would; one whose write has not
                // completed yet (state Pending) rejects with
                // NotAllowedError, same as a fresh
                // requestFileHandle() would for a pending entry.
                let global = self.file_system_handle.global();
                registry::complete_a_read_request_for_file(
                    &global,
                    hash,
                    origin,
                    &promise,
                    global.task_manager().file_reading_task_source().to_sendable(),
                    self.file_system_handle.name(),
                );
            },
        }

        promise
    }

    /// <https://fs.spec.whatwg.org/#dom-filesystemfilehandle-createwritable>
    ///
    /// Simplified: the real algorithm is a permission-check-then-queue-a-task
    /// dance; per this module's doc comment, Cross-Origin Storage handles
    /// need no permission check, and stream construction here cannot fail
    /// in a way that needs deferring, so this resolves synchronously.
    /// `options` (e.g. `keepExistingData`) is accepted for signature
    /// compatibility but not yet consumed.
    fn CreateWritable(
        &self,
        realm: &mut CurrentRealm,
        _options: &FileSystemCreateWritableOptions,
    ) -> Rc<Promise> {
        let promise = Promise::new_in_realm(realm);

        let Backing::Create {
            hash,
            origin,
            requested_origins,
        } = &self.backing
        else {
            // See this module's doc comment: createWritable() on a
            // read-mode handle is not yet supported.
            promise.reject_error(
                realm,
                Error::NotSupported(Some(
                    "createWritable() on a handle not obtained via options.create is not yet \
                     supported"
                        .to_owned(),
                )),
            );
            return promise;
        };

        match FileSystemWritableFileStream::new(
            realm,
            &self.file_system_handle.global(),
            hash.clone(),
            origin.clone(),
            requested_origins.clone(),
        ) {
            Ok(stream) => promise.resolve_native(realm, &stream),
            Err(error) => promise.reject_error(realm, error),
        }

        promise
    }
}
