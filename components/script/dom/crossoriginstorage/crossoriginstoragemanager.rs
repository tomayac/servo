/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface>
//!
//! `requestFileHandle()` implements both the read path and the create
//! path end to end, including the `origins` option (`validate a COS
//! request` step 3), by delegating to `registry.rs` and constructing
//! either a read- or create-backed `FileSystemFileHandle` (see
//! `filesystemfilehandle.rs`). The create path's actual writing happens
//! later, when script calls `createWritable()` on the resulting handle and
//! writes to/closes the returned `FileSystemWritableFileStream`; see that
//! module and `stream/writablestreamdefaultcontroller.rs`'s
//! `UnderlyingSinkType::CrossOriginStorageWrite` for how that is wired.
//!
//! Known simplifications, beyond what `registry.rs` and
//! `filesystemfilehandle.rs` already document:
//! - A malformed candidate in `options.origins` rejects the whole request
//!   with a `TypeError`, per spec step 3; this part is implemented for
//!   real, not simplified.
//! - `options.origins`'s own `maximum origins list length` is enforced
//!   here (see `RequestFileHandle`'s length check right after calling
//!   `validate_and_normalize_requested_origins`) with a `TypeError`
//!   before any write is attempted, per
//!   <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>.
//!   See `net_traits::cross_origin_storage_thread::MAX_ORIGINS_LIST_LENGTH`'s
//!   doc comment for the shared constant and the *merge*-time counterpart
//!   of this same limit in `net::cross_origin_storage_thread::upgrade_resource_visibility`.

use std::ffi::CString;
use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use servo_url::{ImmutableOrigin, ServoUrl};

use crate::dom::bindings::codegen::Bindings::CrossOriginStorageManagerBinding::{
    CrossOriginStorageManagerMethods, CrossOriginStorageRequestFileHandleHash,
    CrossOriginStorageRequestFileHandleOptions,
};
use crate::dom::bindings::codegen::UnionTypes::StringOrStringSequence;
use crate::dom::bindings::error::Error;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::{DOMString, USVString};
use crate::dom::crossoriginstorage::filesystemfilehandle::FileSystemFileHandle;
use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::crossoriginstorage::registry::{self, MAX_ORIGINS_LIST_LENGTH, RequestedOrigins};
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

/// <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>
/// step-3-adjacent: this also performs the *validation* half of spec
/// step 3 (parse failure or opaque origin -> reject), which the real spec
/// splits across `validate a COS request` (validation) and `normalize
/// requested origins` (used later, at write-verification time). Combined
/// here since both need the same per-candidate parsing.
///
/// Returns `Err(())` for a malformed candidate (caller should reject with
/// `TypeError`); `Ok(None)` if `origins` was not supplied at all;
/// `Ok(Some(...))` otherwise. `maximum origins list length` is checked
/// by the caller instead, right after this returns; see
/// `RequestFileHandle`'s doc comment.
fn validate_and_normalize_requested_origins(
    origins: &Option<StringOrStringSequence>,
) -> Result<Option<RequestedOrigins>, ()> {
    let Some(origins) = origins else {
        return Ok(None);
    };

    let candidates: Vec<DOMString> = match origins {
        StringOrStringSequence::String(s) if *s == "*" => {
            return Ok(Some(RequestedOrigins::Wildcard));
        },
        StringOrStringSequence::String(s) => vec![s.clone()],
        StringOrStringSequence::StringSequence(list) => list.clone(),
    };

    let mut parsed = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let Ok(url) = ServoUrl::parse(&candidate.to_string()) else {
            return Err(());
        };
        let origin = url.origin();
        if matches!(origin, ImmutableOrigin::Opaque(_)) {
            return Err(());
        }
        if !parsed.contains(&origin) {
            parsed.push(origin);
        }
    }

    Ok(Some(RequestedOrigins::List(parsed)))
}

impl CrossOriginStorageManagerMethods<crate::DomTypeHolder> for CrossOriginStorageManager {
    /// <https://wicg.github.io/cross-origin-storage/#dom-crossoriginstoragemanager-requestfilehandle>
    ///
    /// See this module's doc comment for what is and is not yet
    /// implemented. Resolves/rejects via a queued task rather than the
    /// spec's Cross-Origin Storage queue; see `registry.rs`'s doc comment
    /// for what that does and does not mean in this implementation.
    fn RequestFileHandle(
        &self,
        realm: &mut CurrentRealm,
        hash: &CrossOriginStorageRequestFileHandleHash,
        options: &CrossOriginStorageRequestFileHandleOptions,
    ) -> Rc<Promise> {
        let promise = Promise::new_in_realm(realm);

        // `validate a COS request`, steps 1-2 (hash shape).
        let cos_hash = CosHash {
            algorithm: hash.algorithm.to_string(),
            value: hash.value.to_string(),
        };
        if cos_hash.validate().is_err() {
            promise.reject_error(realm, Error::Type(c"Malformed COS hash".to_owned()));
            return promise;
        }

        // `validate a COS request`, step 3 (origins shape/parseability).
        let requested_origins = match validate_and_normalize_requested_origins(&options.origins) {
            Ok(requested_origins) => requested_origins,
            Err(()) => {
                promise.reject_error(
                    realm,
                    Error::Type(c"Malformed entry in options.origins".to_owned()),
                );
                return promise;
            },
        };

        // <https://wicg.github.io/cross-origin-storage/#normalize-requested-origins>:
        // "If origins is a list longer than [the implementation-defined
        // maximum length], the user agent must throw a TypeError before
        // attempting any write." This is a single call's own list, not
        // the (separately handled, silently-truncated) merge case; see
        // `MAX_ORIGINS_LIST_LENGTH`'s doc comment.
        if let Some(RequestedOrigins::List(list)) = &requested_origins {
            if list.len() > MAX_ORIGINS_LIST_LENGTH {
                promise.reject_error(
                    realm,
                    Error::Type(
                        CString::new(format!(
                            "options.origins exceeds the maximum length of {MAX_ORIGINS_LIST_LENGTH}"
                        ))
                        .unwrap(),
                    ),
                );
                return promise;
            }
        }

        let origin = self.global().origin().immutable().clone();
        let name = USVString::from(cos_hash.value.clone());

        if options.create {
            // `complete a create request`.
            registry::complete_a_create_request(&self.global(), &cos_hash, &origin, requested_origins.clone());
            let handle = FileSystemFileHandle::new_for_create(
                realm,
                &self.global(),
                name,
                cos_hash,
                origin,
                requested_origins,
            );
            promise.resolve_native(realm, &handle);
            return promise;
        }

        // `complete a read request`. Resolves/rejects `promise`
        // asynchronously; see `registry.rs`'s doc comment.
        registry::complete_a_read_request(
            &self.global(),
            &cos_hash,
            &origin,
            &promise,
            self.global().task_manager().file_reading_task_source().to_sendable(),
            name,
        );

        promise
    }
}
