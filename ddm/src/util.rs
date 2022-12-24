use std::mem::MaybeUninit;

//TODO trade for `MaybeUninit::slice_assume_init_ref` when it becomes available
//in stable Rust.
#[inline(always)]
pub(crate) const unsafe fn u8_slice_assume_init_ref(
    slice: &[MaybeUninit<u8>],
) -> &[u8] {
    unsafe { &*(slice as *const [MaybeUninit<u8>] as *const [u8]) }
}
