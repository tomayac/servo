/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface>
//!
//! `requestFileHandle()` implements the real registry algorithms (see
//! `registry.rs`) for the read path. `options.create` still rejects
//! `NotSupportedError`: even though the registry itself now supports
//! `complete a create request` and `verify and store`, there is currently
//! no way to reach them from script, because `FileSystemWritableFileStream`
//! does not exist yet. See `registry.rs` and
//! `stream/writablestreamdefaultcontroller.rs`'s
//! `UnderlyingSinkType::CrossOriginStorageWrite` for exactly how far that
//! work has gotten and precisely what remains; the short version is that
//! the write algorithm's chunk-to-bytes conversion is unimplemented, and
//! `FileSystemWritableFileStream : WritableStream` cannot yet be
//! constructed at all, because `WritableStream`'s own constructors are not
//! currently structured to support subclassing the way `Blob`/`File` are.
//!
//! The `origins` option validation in `validate a COS request` step 3 is
//! also not yet implemented, since nothing yet consumes `origins` on a
//! reachable write path.

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
use crate::dom::crossoriginstorage::registry::{self, ReadOutcome};
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
    /// spec's Cross-Origin Storage queue, since `registry`'s operations
    /// are same-thread, in-memory, and cannot themselves fail
    /// asynchronously today; see `registry.rs`'s doc comment for what
    /// "in-memory" does and does not mean here.
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
                    "Cross-Origin Storage's write path (options.create) is not yet reachable \
                     from script; see this module's doc comment"
                        .to_owned(),
                )),
            );
            return promise;
        }

        let origin = self.global().origin().immutable().clone();
        match registry::complete_a_read_request(&cos_hash, &origin) {
            ReadOutcome::Found(entry) => {
                // A COS entry has no developer-meaningful name (entries
                // are identified purely by hash); see
                // filesystemfilehandle.rs's `new()` doc comment for the
                // placeholder used here.
                let name = USVString::from(cos_hash.value.clone());
                let handle = FileSystemFileHandle::new(realm, &self.global(), name, entry);
                promise.resolve_native(realm, &handle);
            },
            ReadOutcome::NotFound => {
                promise.reject_error(realm, Error::NotFound(None));
            },
            ReadOutcome::PendingWrite => {
                promise.reject_error(realm, Error::NotAllowed(None));
            },
        }

        promise
    }
}
