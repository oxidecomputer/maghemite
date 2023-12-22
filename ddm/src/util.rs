// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::mem::MaybeUninit;

//TODO trade for `MaybeUninit::slice_assume_init_ref` when it becomes available
//in stable Rust.
#[inline(always)]
pub(crate) const unsafe fn u8_slice_assume_init_ref(
    slice: &[MaybeUninit<u8>],
) -> &[u8] {
    unsafe { &*(slice as *const [MaybeUninit<u8>] as *const [u8]) }
}
