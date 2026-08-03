/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://wicg.github.io/cross-origin-storage/#the-crossoriginstoragemanager-interface
//
// See crossoriginstoragemanager.rs for what is and is not yet
// implemented.

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
