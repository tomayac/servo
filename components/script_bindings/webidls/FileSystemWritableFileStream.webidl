/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://fs.spec.whatwg.org/#filesystemwritablefilestream
//
// NOTE: this is a minimal, Cross-Origin-Storage-scoped subset. See
// crossoriginstorage/filesystemwritablefilestream.rs for exactly what
// write()/seek()/truncate() do and do not implement.
//
// Deliberately omitted: close() convenience method -- the inherited
// WritableStream.close() already works unmodified.

enum WriteCommandType {
  "write",
  "seek",
  "truncate",
};

// `data`'s real type is `(BufferSource or Blob or USVString)?`; it is
// `any` here because `write()` below likewise takes `any` and hand-rolls
// its own conversion (see this module's doc comment for why), so `data`
// is parsed the same way once a `WriteParams` dictionary is recognized.
dictionary WriteParams {
  required WriteCommandType type;
  unsigned long long? size;
  unsigned long long? position;
  any data;
};

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface FileSystemWritableFileStream : WritableStream {
  [NewObject] Promise<undefined> write(any data);
  [NewObject] Promise<undefined> seek([EnforceRange] unsigned long long position);
  [NewObject] Promise<undefined> truncate([EnforceRange] unsigned long long size);
};
