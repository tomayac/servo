/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface>
//!
//! `requestFileHandle()` currently implements only the read path (`options`
//! unset, or `options.create` false), and only the hash-shape half of
//! `validate a COS request` (see `hash::CosHash::validate()`); the
//! `origins` option checks are not yet implemented, since nothing yet
//! consumes `origins` on the write path they exist to constrain.
//!
//! Registry lookups go through `stub_registry`, a process-local,
//! non-persistent, non-spec-conformant stand-in -- see its module doc for
//! exactly what that does and does not implement. In particular, there is
//! currently no way for script to populate it (no write path), so every
//! `requestFileHandle()` call against an unmodified build will reject with
//! `NotFoundError`, correctly for an empty registry, but not because
//! availability gating, the Public Hash List, or GREASE'ing are actually
//! implemented.
//!
//! Follow-up work, roughly in dependency order:
//! 1. `options.create` / the write path: `FileSystemWritableFileStream`,
//!    which needs a native (Rust-backed) underlying-sink variant in
//!    `WritableStreamDefaultController` that does not exist yet (today it
//!    only supports `Js` and `Transfer` sinks). `WritableStream` itself is
//!    otherwise already implemented in Servo and can be reused directly
//!    once that gap is closed.
//! 2. The real COS registry (hash -> entry map, `origins` scoping,
//!    storing-origins bookkeeping, availability gating, PHL, GREASE'ing)
//!    per <https://wicg.github.io/cross-origin-storage/#cos-entries>,
//!    replacing `stub_registry` rather than growing alongside it.
//! 3. The `origins` option validation in `validate a COS request` step 3.

use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};

use crate::dom::bindings::codegen::Bindings::CrossOriginStorageManagerBinding::{
    CrossOriginStorageManagerMethods, CrossOriginStorageRequestFileHandleHash,
    CrossOriginStorageRequestFileHandleOptions,
};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::USVString;
use crate::dom::crossoriginstorage::filesystemfilehandle::FileSystemFileHandle;
use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::crossoriginstorage::stub_registry;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;

#[dom_struct]
pub(crate) struct CrossOriginStorageManager {
    reflector_: Reflector,
}

impl CrossOriginStorageManager {
    fn new_inherited() -> CrossOriginStorageManager {
        CrossOriginStorageManager {
            reflector_: Reflector::new(),
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
    ) -> DomRoot<CrossOriginStorageManager> {
        reflect_dom_object_with_cx(
            Box::new(CrossOriginStorageManager::new_inherited()),
            global,
            cx,
        )
    }
}

impl CrossOriginStorageManagerMethods<crate::DomTypeHolder> for CrossOriginStorageManager {
    /// <https://wicg.github.io/cross-origin-storage/#dom-crossoriginstoragemanager-requestfilehandle>
    ///
    /// See this module's doc comment for what is and is not yet
    /// implemented. Resolves/rejects synchronously rather than via the
    /// spec's Cross-Origin Storage queue, since `stub_registry` is a
    /// same-thread in-memory lookup with no actual asynchrony; a real
    /// registry-backed implementation should revisit this (the spec
    /// requires registry operations to be enqueued so they execute in
    /// order without interleaving, which matters once there is a write
    /// path that could race with reads).
    fn RequestFileHandle(
        &self,
        realm: &mut CurrentRealm,
        hash: &CrossOriginStorageRequestFileHandleHash,
        options: &CrossOriginStorageRequestFileHandleOptions,
    ) -> Rc<Promise> {
        let promise = Promise::new_in_realm(realm);

        // `validate a COS request`, steps 1-2 (hash shape only; see this
        // module's doc comment re: step 3, the `origins` option checks).
        let cos_hash = CosHash {
            algorithm: hash.algorithm.to_string(),
            value: hash.value.to_string(),
        };
        if cos_hash.validate().is_err() {
            promise.reject_error(realm, Error::Type(c"Malformed COS hash".to_owned()));
            return promise;
        }

        if options.create {
            promise.reject_error(
                realm,
                Error::NotSupported(Some(
                    "Cross-Origin Storage's write path (options.create) is not yet implemented"
                        .to_owned(),
                )),
            );
            return promise;
        }

        // `complete a read request`, against the stub registry rather than
        // the real one; see this module's doc comment.
        match stub_registry::get(&cos_hash) {
            Some(entry) => {
                // A COS entry has no developer-meaningful name (entries are
                // identified purely by hash); see filesystemfilehandle.rs's
                // `new()` doc comment for the placeholder used here.
                let name = USVString::from(cos_hash.value.clone());
                let handle = FileSystemFileHandle::new(realm, &self.global(), name, entry);
                promise.resolve_native(realm, &handle);
            },
            None => {
                promise.reject_error(realm, Error::NotFound(None));
            },
        }

        promise
    }
}
