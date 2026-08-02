/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://fs.spec.whatwg.org/#filesystemhandle>
//!
//! See `FileSystemHandle.webidl` for the scope note: this is a minimal,
//! Cross-Origin-Storage-scoped subset (`kind`, `name` only), not a general
//! File System Access API implementation. A future full implementation of
//! the File System Standard should likely absorb or replace this rather
//! than grow alongside it.

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};

use crate::dom::bindings::codegen::Bindings::FileSystemHandleBinding::{
    FileSystemHandleKind, FileSystemHandleMethods,
};
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::USVString;
use crate::dom::globalscope::GlobalScope;

#[dom_struct]
pub(crate) struct FileSystemHandle {
    reflector_: Reflector,
    kind: FileSystemHandleKind,
    name: USVString,
}

impl FileSystemHandle {
    pub(crate) fn new_inherited(kind: FileSystemHandleKind, name: USVString) -> FileSystemHandle {
        FileSystemHandle {
            reflector_: Reflector::new(),
            kind,
            name,
        }
    }

    #[expect(dead_code, reason = "not yet used outside of FileSystemFileHandle")]
    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        kind: FileSystemHandleKind,
        name: USVString,
    ) -> DomRoot<FileSystemHandle> {
        reflect_dom_object_with_cx(
            Box::new(FileSystemHandle::new_inherited(kind, name)),
            global,
            cx,
        )
    }

    pub(crate) fn kind(&self) -> FileSystemHandleKind {
        self.kind.clone()
    }

    pub(crate) fn name(&self) -> USVString {
        self.name.clone()
    }
}

impl FileSystemHandleMethods<crate::DomTypeHolder> for FileSystemHandle {
    /// <https://fs.spec.whatwg.org/#dom-filesystemhandle-kind>
    fn Kind(&self) -> FileSystemHandleKind {
        self.kind()
    }

    /// <https://fs.spec.whatwg.org/#dom-filesystemhandle-name>
    fn Name(&self) -> USVString {
        self.name()
    }
}
