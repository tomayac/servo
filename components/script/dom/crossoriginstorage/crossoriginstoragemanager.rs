/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface>
//!
//! `CrossOriginStorageManager` currently exposes no methods (see
//! `CrossOriginStorageManager.webidl` for why `requestFileHandle()` is not
//! yet wired up). This lands `navigator.crossOriginStorage` as a real,
//! reachable object so the surrounding plumbing (Pref gating, Navigator /
//! WorkerNavigator wiring) can be reviewed and landed independently of the
//! larger `requestFileHandle()` implementation.
//!
//! Follow-up work, roughly in dependency order:
//! 1. A minimal, COS-scoped `FileSystemFileHandle` /
//!    `FileSystemWritableFileStream` pair (reusing `WritableStream`, which
//!    already exists) rather than a full File System Access API
//!    implementation; see discussion on the tracking issue.
//! 2. An in-process COS registry (hash -> entry map) per
//!    <https://wicg.github.io/cross-origin-storage/#cos-entries>, initially
//!    in-memory / non-persistent.
//! 3. `requestFileHandle()` itself, wired to `hash::CosHash::validate()`
//!    (already implemented) for the hash-shape checks, then to the
//!    registry.

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};

use crate::dom::bindings::root::DomRoot;
use crate::dom::globalscope::GlobalScope;

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
