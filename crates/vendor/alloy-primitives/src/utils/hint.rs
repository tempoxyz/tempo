#![allow(dead_code)]

#[inline(always)]
#[cfg_attr(not(feature = "nightly"), cold)]
pub(crate) const fn cold_path() {
    #[cfg(feature = "nightly")]
    core::intrinsics::cold_path();
}

#[inline(always)]
pub(crate) const fn likely(b: bool) -> bool {
    #[cfg(feature = "nightly")]
    return core::intrinsics::likely(b);

    #[cfg(not(feature = "nightly"))]
    if b {
        true
    } else {
        cold_path();
        false
    }
}

#[inline(always)]
pub(crate) const fn unlikely(b: bool) -> bool {
    #[cfg(feature = "nightly")]
    return core::intrinsics::unlikely(b);

    #[cfg(not(feature = "nightly"))]
    if b {
        cold_path();
        true
    } else {
        false
    }
}
