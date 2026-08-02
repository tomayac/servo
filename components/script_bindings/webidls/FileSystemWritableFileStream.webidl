/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://fs.spec.whatwg.org/#filesystemwritablefilestream
//
// NOTE: this is a minimal, Cross-Origin-Storage-scoped subset. Adds no
// members of its own on top of WritableStream. See
// crossoriginstorage/filesystemwritablefilestream.rs for the scope
// rationale, including why that's not a functional gap: writing and
// closing both work via the inherited WritableStream API already.
//
// Deliberately omitted: write(), seek(), truncate(), close() convenience
// methods.

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface FileSystemWritableFileStream : WritableStream {
};
