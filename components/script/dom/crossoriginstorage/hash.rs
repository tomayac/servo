/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! `CosHash` lives in `net_traits::cross_origin_storage_thread`, since
//! both `script` (to construct requests) and `net` (to own the registry)
//! need it, and `net` cannot depend on `script`. Re-exported here so
//! callers throughout this module tree can refer to it as
//! `crate::dom::crossoriginstorage::hash::CosHash`.

pub(crate) use net_traits::cross_origin_storage_thread::CosHash;
