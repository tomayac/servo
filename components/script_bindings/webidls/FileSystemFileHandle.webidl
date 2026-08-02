/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

// https://fs.spec.whatwg.org/#filesystemfilehandle
//
// NOTE: this is a minimal, Cross-Origin-Storage-scoped subset. See
// FileSystemHandle.webidl for the general scope rationale.
//
// Deliberately omitted:
// - createSyncAccessHandle(): not used by the COS spec at all.
//
// createWritable() is implemented, but only for handles obtained via
// requestFileHandle(hash, {create: true}); see
// crossoriginstorage/filesystemfilehandle.rs's module doc for exactly
// what that does and does not cover, and
// crossoriginstorage/filesystemwritablefilestream.rs for the resulting
// stream's own scope.

[Exposed=(Window,Worker), SecureContext, Pref="dom_cross_origin_storage_enabled"]
interface FileSystemFileHandle : FileSystemHandle {
  [NewObject]
  Promise<File> getFile();

  [NewObject]
  Promise<FileSystemWritableFileStream> createWritable(
      optional FileSystemCreateWritableOptions options = {});
};

dictionary FileSystemCreateWritableOptions {
  boolean keepExistingData = false;
};
