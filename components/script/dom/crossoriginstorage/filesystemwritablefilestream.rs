/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! <https://fs.spec.whatwg.org/#filesystemwritablefilestream>
//!
//! Adds `write()`, `seek()`, and `truncate()` convenience methods on top
//! of the base `WritableStream` (`close()` needs no override: the
//! inherited `WritableStream.close()` already works unmodified and
//! triggers `verify_and_store`, since this is wired to a real
//! `UnderlyingSinkType::CrossOriginStorageWrite` controller -- see
//! `stream/writablestreamdefaultcontroller.rs`). A page can write and
//! close via either the convenience methods:
//!
//! ```js
//! const handle = await navigator.crossOriginStorage.requestFileHandle(hash, {create: true});
//! const writable = await handle.createWritable();
//! await writable.write(new Uint8Array([...])); // or a Blob
//! await writable.close(); // triggers verify_and_store
//! ```
//!
//! or the lower-level `getWriter()`/`writer.write()`/`writer.close()` API,
//! which `write()` is implemented in terms of (acquire a writer, write,
//! release the lock -- see `Write()` below).
//!
//! `write()` accepts the full real chunk union -- `ArrayBuffer`,
//! `ArrayBufferView`, `Blob`, `USVString`, or a `WriteParams` dictionary
//! (`{type: "write"|"seek"|"truncate", position, size, data}`, letting a
//! single `write()` call also seek or truncate) -- via manual conversion
//! in the `CrossOriginStorageWrite` write algorithm in
//! `stream/writablestreamdefaultcontroller.rs`; `data` is forwarded to
//! the writer verbatim (`write(any data)`), so that algorithm is where
//! the actual chunk-type dispatch happens, not here.
//!
//! `seek()` and `truncate()` are both real: per
//! <https://fs.spec.whatwg.org/#filesystemwritablefilestream> the sink
//! tracks a `[[position]]` slot into the accumulated write buffer.
//! `write()` writes at the current position and advances it;
//! `seek()` sets the position directly (a later `write()` past the
//! current end of the buffer zero-pads the gap, matching the spec's
//! "write command" algorithm); `truncate()` resizes the buffer and
//! clamps the position down if it now exceeds the new size. See
//! `WritableStreamDefaultController::cross_origin_storage_seek` and
//! `cross_origin_storage_truncate`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use dom_struct::dom_struct;
use js::realm::CurrentRealm;
use js::rust::HandleValue as SafeHandleValue;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_url::ImmutableOrigin;

use crate::dom::bindings::codegen::Bindings::FileSystemWritableFileStreamBinding::FileSystemWritableFileStreamMethods;
use crate::dom::bindings::codegen::Bindings::QueuingStrategyBinding::QueuingStrategy;
use crate::dom::bindings::error::{Error, Fallible};
use crate::dom::bindings::root::DomRoot;
use crate::dom::crossoriginstorage::hash::CosHash;
use crate::dom::crossoriginstorage::registry::RequestedOrigins;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;
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
            position: Cell::new(0),
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

impl FileSystemWritableFileStreamMethods<crate::DomTypeHolder> for FileSystemWritableFileStream {
    /// <https://fs.spec.whatwg.org/#dom-filesystemwritablefilestream-write>
    /// "Let writer be the result of getting a writer for this. Let result
    /// be the result of writing a chunk to writer given data. Release
    /// writer's lock. Return result." -- `data` is forwarded to the
    /// writer verbatim; the sink's write algorithm (not this method) is
    /// what recognizes and unwraps a `WriteParams` chunk. See this
    /// module's doc comment for which chunk types the sink accepts.
    fn Write(&self, realm: &mut CurrentRealm, data: SafeHandleValue) -> Rc<Promise> {
        let global = GlobalScope::from_current_realm(realm);
        let writer = match self.writable_stream.aquire_default_writer(realm, &global) {
            Ok(writer) => writer,
            Err(error) => {
                let promise = Promise::new(realm, &global);
                promise.reject_error(realm, error);
                return promise;
            },
        };
        let promise = writer.write(realm, &global, data);
        writer.release(realm, &global);
        promise
    }

    /// <https://fs.spec.whatwg.org/#dom-filesystemwritablefilestream-seek>
    fn Seek(&self, realm: &mut CurrentRealm, position: u64) -> Rc<Promise> {
        let global = GlobalScope::from_current_realm(realm);
        let promise = Promise::new(realm, &global);
        if !self.writable_stream.is_writable() {
            promise.reject_error(realm, Error::Type(c"Stream is not writable".to_owned()));
            return promise;
        }
        let Some(controller) = self.writable_stream.get_controller() else {
            promise.reject_error(realm, Error::Type(c"Stream has no controller".to_owned()));
            return promise;
        };
        controller.cross_origin_storage_seek(position as usize);
        promise.resolve_native(realm, &());
        promise
    }

    /// <https://fs.spec.whatwg.org/#dom-filesystemwritablefilestream-truncate>
    fn Truncate(&self, realm: &mut CurrentRealm, size: u64) -> Rc<Promise> {
        let global = GlobalScope::from_current_realm(realm);
        let promise = Promise::new(realm, &global);
        if !self.writable_stream.is_writable() {
            promise.reject_error(realm, Error::Type(c"Stream is not writable".to_owned()));
            return promise;
        }
        let Some(controller) = self.writable_stream.get_controller() else {
            promise.reject_error(realm, Error::Type(c"Stream has no controller".to_owned()));
            return promise;
        };
        controller.cross_origin_storage_truncate(size as usize);
        promise.resolve_native(realm, &());
        promise
    }
}
