/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://fs.spec.whatwg.org/#filesystemhandle
//
// NOTE: this is a minimal, Cross-Origin-Storage-scoped subset of the File
// System Standard's FileSystemHandle, not a general File System Access API
// implementation. See crossoriginstorage/filesystemhandle.rs for the scope
// rationale.
//
// Deliberately omitted, and not needed by Cross-Origin Storage:
// - isSameEntry(): entry-identity comparison, not used by the COS spec.
// - queryPermission() / requestPermission(): per
//   https://wicg.github.io/cross-origin-storage/#cos-file-system, "the
//   Cross-Origin Storage file system does not use [FS]'s ordinary per-call
//   permission-check model" -- every handle COS hands out is already fully
//   authorized, so these methods would be actively misleading to include.

enum FileSystemHandleKind { "file", "directory" };

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface FileSystemHandle {
  readonly attribute FileSystemHandleKind kind;
  readonly attribute USVString name;
};
