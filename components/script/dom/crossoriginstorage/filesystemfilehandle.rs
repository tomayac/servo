/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://fs.spec.whatwg.org/#filesystemfilehandle>
//!
//! See `FileSystemFileHandle.webidl` for what is deliberately omitted
//! (`createWritable()`, `createSyncAccessHandle()`) and why.
//!
//! Per <https://wicg.github.io/cross-origin-storage/#cos-file-system>, every
//! handle obtained from Cross-Origin Storage is already fully authorized
//! before being returned to script, so `getFile()` here never triggers a
//! permission prompt -- there is no permission-check machinery to call in
//! the first place, which matches the spec's intent rather than being an
//! oversight.

use std::rc::Rc;
use std::time::SystemTime;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_constellation_traits::BlobImpl;

use crate::dom::bindings::codegen::Bindings::FileSystemFileHandleBinding::FileSystemFileHandleMethods;
use crate::dom::bindings::codegen::Bindings::FileSystemHandleBinding::FileSystemHandleKind;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::{DOMString, USVString};
use crate::dom::crossoriginstorage::filesystemhandle::FileSystemHandle;
use crate::dom::crossoriginstorage::registry::EntryBytes;
use crate::dom::file::File;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;

#[dom_struct]
pub(crate) struct FileSystemFileHandle {
    file_system_handle: FileSystemHandle,
    #[no_trace]
    entry: EntryBytes,
}

impl FileSystemFileHandle {
    fn new_inherited(name: USVString, entry: EntryBytes) -> FileSystemFileHandle {
        FileSystemFileHandle {
            file_system_handle: FileSystemHandle::new_inherited(FileSystemHandleKind::File, name),
            entry,
        }
    }

    /// Construct a handle for a COS entry already found in the (stub)
    /// registry. `name` is not part of a COS entry per the real spec (a
    /// `FileSystemFileHandle` from Cross-Origin Storage has no
    /// developer-meaningful name; entries are identified purely by hash),
    /// so callers currently pass the hash's `value` as a placeholder. A
    /// real registry implementation should revisit this once `name`'s
    /// actual role in `getFile()`'s resulting `File.name` is pinned down
    /// against the spec text.
    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        name: USVString,
        entry: EntryBytes,
    ) -> DomRoot<FileSystemFileHandle> {
        reflect_dom_object_with_cx(
            Box::new(FileSystemFileHandle::new_inherited(name, entry)),
            global,
            cx,
        )
    }
}

impl FileSystemFileHandleMethods<crate::DomTypeHolder> for FileSystemFileHandle {
    /// <https://fs.spec.whatwg.org/#dom-filesystemfilehandle-getfile>
    ///
    /// Simplified relative to the full File System Standard algorithm:
    /// that algorithm round-trips through an I/O task queue because a
    /// general handle can be backed by disk I/O with real latency and
    /// failure modes. Our stub registry is an in-memory `HashMap` lookup
    /// that cannot meaningfully fail, so this resolves synchronously
    /// instead of queuing a task. A real registry-backed implementation
    /// (see registry.rs's module docs) should revisit this once reads
    /// can actually fail or block.
    fn GetFile(&self, realm: &mut CurrentRealm) -> Rc<Promise> {
        let promise = Promise::new_in_realm(realm);

        let blob_impl =
            BlobImpl::new_from_bytes(self.entry.bytes.clone(), self.entry.type_string.clone());
        let name = DOMString::from(self.file_system_handle.name().to_string());
        let file = File::new(
            realm,
            &self.file_system_handle.global(),
            blob_impl,
            name,
            Some(SystemTime::now()),
        );

        promise.resolve_native(realm, &file);
        promise
    }
}
