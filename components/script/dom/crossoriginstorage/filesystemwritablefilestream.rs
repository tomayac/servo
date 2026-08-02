/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://fs.spec.whatwg.org/#filesystemwritablefilestream>
//!
//! Adds zero of its own methods. The real File System Standard interface
//! also has convenience `write()`, `seek()`, `truncate()`, and `close()`
//! methods on top of the base `WritableStream`; none of those are
//! implemented here. This is not a functional gap for testing the write
//! path: a `FileSystemWritableFileStream` already *is* a `WritableStream`,
//! and the base `WritableStream`/`WritableStreamDefaultWriter` API
//! (`getWriter()`, `writer.write(chunk)`, `writer.close()`) is fully
//! implemented in Servo already and works unmodified against this
//! subclass, since it is wired to a real
//! `UnderlyingSinkType::CrossOriginStorageWrite` controller (see
//! `stream/writablestreamdefaultcontroller.rs`). A page can write and
//! close via:
//!
//! ```js
//! const handle = await navigator.crossOriginStorage.requestFileHandle(hash, {create: true});
//! const writable = await handle.createWritable();
//! const writer = writable.getWriter();
//! await writer.write(new Uint8Array([...]));
//! await writer.close(); // triggers verify_and_store
//! ```
//!
//! The `seek()`/`truncate()` omission is a real, if minor, semantic gap
//! (not just missing sugar): COS's model is "write the complete file
//! contents", so random-access rewriting is out of scope, and adding
//! those methods later should not be assumed to be a small addition
//! without checking whether COS's `verify_and_store` (which hashes the
//! complete written byte sequence) has any sensible interaction with them
//! at all.

use std::cell::RefCell;

use dom_struct::dom_struct;
use js::realm::CurrentRealm;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_url::ImmutableOrigin;

use crate::dom::bindings::codegen::Bindings::QueuingStrategyBinding::QueuingStrategy;
use crate::dom::bindings::error::Fallible;
use crate::dom::bindings::root::DomRoot;
use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::crossoriginstorage::registry::RequestedOrigins;
use crate::dom::globalscope::GlobalScope;
use crate::dom::stream::countqueuingstrategy::{extract_high_water_mark, extract_size_algorithm};
use crate::dom::stream::writablestream::{
    WritableStream, setup_writable_stream_default_controller_for,
};
use crate::dom::stream::writablestreamdefaultcontroller::UnderlyingSinkType;

#[dom_struct]
pub(crate) struct FileSystemWritableFileStream {
    writable_stream: WritableStream,
}

impl FileSystemWritableFileStream {
    fn new_inherited() -> FileSystemWritableFileStream {
        FileSystemWritableFileStream {
            writable_stream: WritableStream::new_inherited(),
        }
    }

    /// Construct a `FileSystemWritableFileStream` backed by Cross-Origin
    /// Storage's write path
    /// (<https://wicg.github.io/cross-origin-storage/#creating-and-writing-files>).
    ///
    /// `type_string` for the eventual stored entry is not something this
    /// path has any input for (unlike `getFile()`'s read side, nothing
    /// here specifies a MIME type), so it is stored as an empty string,
    /// matching `Blob`'s own default `type` when unspecified.
    pub(crate) fn new(
        realm: &mut CurrentRealm,
        global: &GlobalScope,
        hash: CosHash,
        origin: ImmutableOrigin,
        requested_origins: Option<RequestedOrigins>,
    ) -> Fallible<DomRoot<FileSystemWritableFileStream>> {
        let this = reflect_dom_object_with_cx(
            Box::new(FileSystemWritableFileStream::new_inherited()),
            global,
            realm,
        );

        let underlying_sink_type = UnderlyingSinkType::CrossOriginStorageWrite {
            hash,
            bytes: RefCell::new(Vec::new()),
            type_string: String::new(),
            origin,
            requested_origins: RefCell::new(requested_origins),
        };

        // Spec-default high water mark / size algorithm, per
        // <https://streams.spec.whatwg.org/#create-writable-stream> as
        // used by `WritableStream`'s own constructor when `strategy` is
        // omitted.
        let default_strategy = QueuingStrategy::empty();
        let high_water_mark = extract_high_water_mark(&default_strategy, 1.0)?;
        let size_algorithm = extract_size_algorithm(realm, &default_strategy);

        setup_writable_stream_default_controller_for(
            realm,
            global,
            &this.writable_stream,
            high_water_mark,
            size_algorithm,
            underlying_sink_type,
        )?;

        Ok(this)
    }
}
