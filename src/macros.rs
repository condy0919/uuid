use std::char;

#[doc(hidden)]
#[inline]
pub fn __private_from_digit(u: u8) -> u8 {
    char::from_digit(u32::from(u), 16).unwrap() as u8
}

/// Fast but not fasted format for byte array 
#[doc(hidden)]
#[macro_use]
macro_rules! bytes_format {
    ($out:ident, $in:ident, $idx:expr, $pos1:expr, $pos2:expr) => {
        $out[$pos1] = $crate::macros::__private_from_digit(($in[$idx] & 0xf0) >> 4);
        $out[$pos2] = $crate::macros::__private_from_digit(($in[$idx] & 0x0f) >> 0);
    };

    ($out:ident, $in:ident, $idx:expr, $pos1:expr, $pos2:expr, $($pos:expr),*) => {
        $out[$pos1] = $crate::macros::__private_from_digit(($in[$idx] & 0xf0) >> 4);
        $out[$pos2] = $crate::macros::__private_from_digit(($in[$idx] & 0x0f) >> 0);

        bytes_format!($out, $in, $idx + 1, $($pos),*);
    }
}
