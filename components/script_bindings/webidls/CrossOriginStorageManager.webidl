/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface
//
// NOTE: `requestFileHandle()` is intentionally not yet exposed here. Per the
// spec, it resolves with a `FileSystemFileHandle` reused from the File System
// Standard (https://fs.spec.whatwg.org/#filesystemfilehandle), which does not
// yet exist in this codebase. This file lands the `crossOriginStorage`
// attribute and manager object first; `requestFileHandle()` is expected to
// follow once a minimal, COS-scoped `FileSystemFileHandle` /
// `FileSystemWritableFileStream` pair lands (see tracking issue).

[SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface mixin NavigatorCrossOriginStorage {
  [SameObject, SecureContext] readonly attribute CrossOriginStorageManager crossOriginStorage;
};
Navigator includes NavigatorCrossOriginStorage;
WorkerNavigator includes NavigatorCrossOriginStorage;

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface CrossOriginStorageManager {
  // requestFileHandle() to follow; see note above.
};

// https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface
//
// Retained here, ahead of `requestFileHandle()` itself, so the shape of a
// COS hash is fixed and can be validated (see
// crate::dom::crossoriginstorage::hash) independently of the method that
// will eventually consume it.
dictionary CrossOriginStorageRequestFileHandleHash {
  required DOMString value;
  required DOMString algorithm;
};

dictionary CrossOriginStorageRequestFileHandleOptions {
  boolean create = false;
  (DOMString or sequence<DOMString>) origins;
};
