/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface
//
// NOTE: `requestFileHandle()` currently only implements the read path
// (`options.create` unset or false). Calling it with `create: true` rejects
// with a NotSupportedError; the write path needs
// `FileSystemWritableFileStream`, which itself needs a native
// (Rust-backed) underlying-sink variant in `WritableStreamDefaultController`
// that does not exist yet. See crossoriginstoragemanager.rs.
//
// The read path is additionally backed by a process-local, non-persistent
// stub registry rather than the real Cross-Origin Storage registry; see
// crossoriginstorage/stub_registry.rs for exactly what that does and does
// not implement.

[SecureContext]
interface mixin NavigatorCrossOriginStorage {
  [SameObject, Pref="dom_cross_origin_storage_enabled"] readonly attribute CrossOriginStorageManager crossOriginStorage;
};
Navigator includes NavigatorCrossOriginStorage;
WorkerNavigator includes NavigatorCrossOriginStorage;

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface CrossOriginStorageManager {
  [NewObject]
  Promise<FileSystemFileHandle> requestFileHandle(
      CrossOriginStorageRequestFileHandleHash hash,
      optional CrossOriginStorageRequestFileHandleOptions options = {});
};

dictionary CrossOriginStorageRequestFileHandleHash {
  required DOMString value;
  required DOMString algorithm;
};

dictionary CrossOriginStorageRequestFileHandleOptions {
  boolean create = false;
  (DOMString or sequence<DOMString>) origins;
};
