/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://fs.spec.whatwg.org/#filesystemwritablefilestream
//
// NOTE: this is a minimal, Cross-Origin-Storage-scoped subset. See
// crossoriginstorage/filesystemwritablefilestream.rs for exactly what
// write()/seek()/truncate() do and do not implement (in particular:
// write() accepts BufferSource or Blob, not USVString or WriteParams;
// seek() does not affect where a later write() lands).
//
// Deliberately omitted: close() convenience method -- the inherited
// WritableStream.close() already works unmodified.

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface FileSystemWritableFileStream : WritableStream {
  [NewObject] Promise<undefined> write(any data);
  [NewObject] Promise<undefined> seek([EnforceRange] unsigned long long position);
  [NewObject] Promise<undefined> truncate([EnforceRange] unsigned long long size);
};
