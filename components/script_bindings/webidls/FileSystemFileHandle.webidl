/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://fs.spec.whatwg.org/#filesystemfilehandle
//
// NOTE: this is a minimal, Cross-Origin-Storage-scoped subset. See
// FileSystemHandle.webidl for the general scope rationale.
//
// Deliberately omitted:
// - createWritable(): the write path. Blocked on
//   WritableStreamDefaultController gaining a native (Rust-backed)
//   underlying-sink variant; today it only supports `Js` (script-provided
//   callbacks) and `Transfer` sinks, neither of which fit a COS-verified
//   write. See crossoriginstoragemanager.rs for tracking notes.
// - createSyncAccessHandle(): not used by the COS spec at all.

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface FileSystemFileHandle : FileSystemHandle {
  [NewObject]
  Promise<File> getFile();
};
