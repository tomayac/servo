/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! `CosHash` now lives in `net_traits::cross_origin_storage_thread`, since
//! both `script` (to construct requests) and `net` (to own the registry)
//! need it, and `net` cannot depend on `script`. Re-exported here so
//! existing `crate::dom::crossoriginstorage::hash::CosHash` references
//! elsewhere in this module tree keep working unchanged.

pub(crate) use net_traits::cross_origin_storage_thread::{CosHash, CosHashValidationError};
