// Copyright 2018 condy0919 [at] gmail [dot] com

//! Generate and parse UUIDs.
//!
//! A universally unique identifier (UUID) is a 128-bit number used to identify
//! information in computer systems.
//! The term globally unique identifier (GUID) is also used.
//!
//! When generated according to the standard methods, UUIDs are for practical
//! purposes unique, without depending for their uniqueness on a central
//! registration authority or coordination between the parties generating
//! them, unlike most other numbering schemes.
//!
//! While the probability that a UUID will be duplicated is not zero, it is
//! close enough to zero to be negligible. 

extern crate md5;
extern crate sha1;
extern crate rand;
extern crate libc;

use std::str::{FromStr, from_utf8_unchecked};
use std::fmt;
use std::error;
use std::default;
use std::char;

pub mod node;
pub use node::Node;

pub mod v1;
pub use v1::{Context, TimeClockSequence};
pub mod v2;
pub use v2::Domain;
pub mod v3;
pub mod v4;
pub mod v5;

mod util;
use util::xtob;

/// A UUID represented by a 16 bytes array
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

/// The version of the UUID
#[derive(Debug, PartialEq, Eq)]
pub struct Version(pub u8);

/// The variant of the UUID
#[derive(Debug, PartialEq, Eq)]
pub enum Variant {
    /// Invalid UUID variant
    Invalid = 0,
    /// As described in the RFC4122 Specification
    RFC4122 = 1,
    /// Reserved by the NCS for backward compatibility
    Reserved = 2,
    /// Reserved by Microsoft for backward compatibility
    Microsoft = 3,
    /// Reserved for future use
    Future = 4,
}

/// The invalid UUID error that can throw when parsing str.
#[derive(Debug, Clone)]
pub struct InvalidUuid;

impl FromStr for Uuid {
    type Err = InvalidUuid;

    /// Converts a string to UUID.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut uuid: [u8; 16] = Default::default();

        let s = match s.len() {
            // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            36 => s,

            // urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            45 => {
                if !s.bytes().zip("urn:uuid:".bytes())
                     .all(|(ch, exp)| (ch | 0x20) == exp) {
                    return Err(InvalidUuid);
                }

                &s[9..]
            },

            // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
            38 => &s[1..37],

            // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            32 => {
                let bs = s.as_bytes();

                for i in 0..16 {
                    let v = xtob(bs[2 * i], bs[2 * i + 1]).map_err(|_| InvalidUuid)?;
                    uuid[i] = v;
                }

                return Ok(Uuid(uuid));
            },

            _ => return Err(InvalidUuid),
        };

        let bs = s.as_bytes();
        if bs[8] != b'-' || bs[13] != b'-' || bs[18] != b'-' || bs[23] != b'-' {
            return Err(InvalidUuid);
        }
        for (i, &val) in [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34].iter().enumerate() {
            let v = xtob(bs[val], bs[val + 1]).map_err(|_| InvalidUuid)?;
            uuid[i] = v;
        }
        Ok(Uuid(uuid))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.to_hyphenated_array()))
        }
    }
}

impl default::Default for Uuid {
    fn default() -> Self {
        Uuid::nil()
    }
}

impl Uuid {
    /// namespace for Domain Name System (DNS)
    pub const NAMESPACE_DNS: Self = Self([0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    /// namespace for Uniform Resource Location (URLs)
    pub const NAMESPACE_URL: Self = Self([0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    /// namespace for ISO Object Identifiers (OIDs)
    pub const NAMESPACE_OID: Self = Self([0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    /// namespace for X.500 Distinguished Names (DNs)
    pub const NAMESPACE_X500: Self = Self([0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);

    /// The nil UUID.
    ///
    /// The nil UUID is special form of UUID
    ///
    /// # Example
    ///
    /// Basic usage:
    ///
    /// ```
    /// use yauuid::Uuid;
    ///
    /// let u = Uuid::nil();
    ///
    /// assert_eq!(u.to_string(), "00000000-0000-0000-0000-000000000000");
    /// ```
    pub fn nil() -> Self {
        Uuid([0; 16])
    }

    /// Creates a hyphenated format instance from Uuid
    pub fn to_hyphenated(self) -> Hyphenated {
        Hyphenated(self)
    }

    /// Creates a hyphenated format reference instance from Uuid
    pub fn to_hyphenated_ref(&self) -> HyphenatedRef {
        HyphenatedRef(self)
    }

    #[doc(hidden)]
    fn to_hyphenated_array(&self) -> [u8; 36] {
        let xs = &self.0;
        let from_digit = |u: u8| char::from_digit(u32::from(u), 16).unwrap() as u8;

        let mut bs: [u8; 36] = [b'-'; 36];
        bs[0] = from_digit((xs[0] & 0xf0) >> 4);
        bs[1] = from_digit((xs[0] & 0x0f) >> 0);
        bs[2] = from_digit((xs[1] & 0xf0) >> 4);
        bs[3] = from_digit((xs[1] & 0x0f) >> 0);
        bs[4] = from_digit((xs[2] & 0xf0) >> 4);
        bs[5] = from_digit((xs[2] & 0x0f) >> 0);
        bs[6] = from_digit((xs[3] & 0xf0) >> 4);
        bs[7] = from_digit((xs[3] & 0x0f) >> 0);

        bs[9] = from_digit((xs[4] & 0xf0) >> 4);
        bs[10] = from_digit((xs[4] & 0x0f) >> 0);
        bs[11] = from_digit((xs[5] & 0xf0) >> 4);
        bs[12] = from_digit((xs[5] & 0x0f) >> 0);

        bs[14] = from_digit((xs[6] & 0xf0) >> 4);
        bs[15] = from_digit((xs[6] & 0x0f) >> 0);
        bs[16] = from_digit((xs[7] & 0xf0) >> 4);
        bs[17] = from_digit((xs[7] & 0x0f) >> 0);

        bs[19] = from_digit((xs[8] & 0xf0) >> 4);
        bs[20] = from_digit((xs[8] & 0x0f) >> 0);
        bs[21] = from_digit((xs[9] & 0xf0) >> 4);
        bs[22] = from_digit((xs[9] & 0x0f) >> 0);

        bs[24] = from_digit((xs[10] & 0xf0) >> 4);
        bs[25] = from_digit((xs[10] & 0x0f) >> 0);
        bs[26] = from_digit((xs[11] & 0xf0) >> 4);
        bs[27] = from_digit((xs[11] & 0x0f) >> 0);
        bs[28] = from_digit((xs[12] & 0xf0) >> 4);
        bs[29] = from_digit((xs[12] & 0x0f) >> 0);
        bs[30] = from_digit((xs[13] & 0xf0) >> 4);
        bs[31] = from_digit((xs[13] & 0x0f) >> 0);
        bs[32] = from_digit((xs[14] & 0xf0) >> 4);
        bs[33] = from_digit((xs[14] & 0x0f) >> 0);
        bs[34] = from_digit((xs[15] & 0xf0) >> 4);
        bs[35] = from_digit((xs[15] & 0x0f) >> 0);

        bs
    }

    /// Creates a simple format instance from Uuid
    pub fn to_simple(self) -> Simple {
        Simple(self)
    }

    /// Creates a simple format reference instance from Uuid
    pub fn to_simple_ref(&self) -> SimpleRef {
        SimpleRef(self)
    }

    #[doc(hidden)]
    fn to_simple_array(&self) -> [u8; 32] {
        let xs = &self.0;
        let from_digit = |u: u8| char::from_digit(u32::from(u), 16).unwrap() as u8;

        let mut bs: [u8; 32] = Default::default();
        bs[0] = from_digit((xs[0] & 0xf0) >> 4);
        bs[1] = from_digit((xs[0] & 0x0f) >> 0);
        bs[2] = from_digit((xs[1] & 0xf0) >> 4);
        bs[3] = from_digit((xs[1] & 0x0f) >> 0);
        bs[4] = from_digit((xs[2] & 0xf0) >> 4);
        bs[5] = from_digit((xs[2] & 0x0f) >> 0);
        bs[6] = from_digit((xs[3] & 0xf0) >> 4);
        bs[7] = from_digit((xs[3] & 0x0f) >> 0);

        bs[8] = from_digit((xs[4] & 0xf0) >> 4);
        bs[9] = from_digit((xs[4] & 0x0f) >> 0);
        bs[10] = from_digit((xs[5] & 0xf0) >> 4);
        bs[11] = from_digit((xs[5] & 0x0f) >> 0);

        bs[12] = from_digit((xs[6] & 0xf0) >> 4);
        bs[13] = from_digit((xs[6] & 0x0f) >> 0);
        bs[14] = from_digit((xs[7] & 0xf0) >> 4);
        bs[15] = from_digit((xs[7] & 0x0f) >> 0);

        bs[16] = from_digit((xs[8] & 0xf0) >> 4);
        bs[17] = from_digit((xs[8] & 0x0f) >> 0);
        bs[18] = from_digit((xs[9] & 0xf0) >> 4);
        bs[19] = from_digit((xs[9] & 0x0f) >> 0);

        bs[20] = from_digit((xs[10] & 0xf0) >> 4);
        bs[21] = from_digit((xs[10] & 0x0f) >> 0);
        bs[22] = from_digit((xs[11] & 0xf0) >> 4);
        bs[23] = from_digit((xs[11] & 0x0f) >> 0);
        bs[24] = from_digit((xs[12] & 0xf0) >> 4);
        bs[25] = from_digit((xs[12] & 0x0f) >> 0);
        bs[26] = from_digit((xs[13] & 0xf0) >> 4);
        bs[27] = from_digit((xs[13] & 0x0f) >> 0);
        bs[28] = from_digit((xs[14] & 0xf0) >> 4);
        bs[29] = from_digit((xs[14] & 0x0f) >> 0);
        bs[30] = from_digit((xs[15] & 0xf0) >> 4);
        bs[31] = from_digit((xs[15] & 0x0f) >> 0);

        bs

    }

    /// Creates a urn format instance from Uuid
    pub fn to_urn(self) -> Urn {
        Urn(self)
    }

    /// Creates a urn format reference instance from Uuid
    pub fn to_urn_ref(&self) -> UrnRef {
        UrnRef(self)
    }

    #[doc(hidden)]
    fn to_urn_array(&self) -> [u8; 45] {
        let xs = &self.0;
        let from_digit = |u: u8| char::from_digit(u32::from(u), 16).unwrap() as u8;

        let mut bs: [u8; 45] = [b'-'; 45];
        bs[0..=8].copy_from_slice(b"urn:uuid:");

        bs[9] = from_digit((xs[0] & 0xf0) >> 4);
        bs[10] = from_digit((xs[0] & 0x0f) >> 0);
        bs[11] = from_digit((xs[1] & 0xf0) >> 4);
        bs[12] = from_digit((xs[1] & 0x0f) >> 0);
        bs[13] = from_digit((xs[2] & 0xf0) >> 4);
        bs[14] = from_digit((xs[2] & 0x0f) >> 0);
        bs[15] = from_digit((xs[3] & 0xf0) >> 4);
        bs[16] = from_digit((xs[3] & 0x0f) >> 0);

        bs[18] = from_digit((xs[4] & 0xf0) >> 4);
        bs[19] = from_digit((xs[4] & 0x0f) >> 0);
        bs[20] = from_digit((xs[5] & 0xf0) >> 4);
        bs[21] = from_digit((xs[5] & 0x0f) >> 0);

        bs[23] = from_digit((xs[6] & 0xf0) >> 4);
        bs[24] = from_digit((xs[6] & 0x0f) >> 0);
        bs[25] = from_digit((xs[7] & 0xf0) >> 4);
        bs[26] = from_digit((xs[7] & 0x0f) >> 0);

        bs[28] = from_digit((xs[8] & 0xf0) >> 4);
        bs[29] = from_digit((xs[8] & 0x0f) >> 0);
        bs[30] = from_digit((xs[9] & 0xf0) >> 4);
        bs[31] = from_digit((xs[9] & 0x0f) >> 0);

        bs[33] = from_digit((xs[10] & 0xf0) >> 4);
        bs[34] = from_digit((xs[10] & 0x0f) >> 0);
        bs[35] = from_digit((xs[11] & 0xf0) >> 4);
        bs[36] = from_digit((xs[11] & 0x0f) >> 0);
        bs[37] = from_digit((xs[12] & 0xf0) >> 4);
        bs[38] = from_digit((xs[12] & 0x0f) >> 0);
        bs[39] = from_digit((xs[13] & 0xf0) >> 4);
        bs[40] = from_digit((xs[13] & 0x0f) >> 0);
        bs[41] = from_digit((xs[14] & 0xf0) >> 4);
        bs[42] = from_digit((xs[14] & 0x0f) >> 0);
        bs[43] = from_digit((xs[15] & 0xf0) >> 4);
        bs[44] = from_digit((xs[15] & 0x0f) >> 0);

        bs
    }

    /// Returns the variant of the UUID.
    pub fn variant(&self) -> Variant {
        let v = self.0[8];

        if v & 0xc0 == 0x80 {
            return Variant::RFC4122;
        } else if v & 0xe0 == 0xc0 {
            return Variant::Microsoft;
        } else if v & 0xe0 == 0xe0 {
            return Variant::Future;
        }
        return Variant::Reserved;
    }

    /// Returns the version of the UUID.
    pub fn version(&self) -> Version {
        Version(self.0[6] >> 4)
    }

    /// Returns an array of 16 bytes containing the UUID.
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Creates a UUID by a 16 bytes array
    pub fn from_bytes(xs: [u8; 16]) -> Self {
        Uuid(xs)
    }
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Variant::Invalid => write!(f, "Invalid"),
            Variant::RFC4122 => write!(f, "RFC4122"),
            Variant::Reserved => write!(f, "Reserved"),
            Variant::Microsoft => write!(f, "Microsoft"),
            Variant::Future => write!(f, "Future"),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut desc: [u8; 9] = [b'V', b'E', b'R', b'S', b'I', b'O', b'N', b'_', b'0'];
        desc[8] += self.0;

        unsafe {
            f.write_str(from_utf8_unchecked(&desc))
        }
    }
}

impl fmt::Display for InvalidUuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid uuid string")
    }
}

impl error::Error for InvalidUuid {
    fn description(&self) -> &str {
        "invalid uuid string"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

/// A hyphenated format of Uuid which takes ownership of Uuid
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Hyphenated(Uuid);

impl fmt::Display for Hyphenated {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.0.to_hyphenated_array()))
        }
    }
}

/// A hyphenated format of Uuid which takes reference of Uuid
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct HyphenatedRef<'a>(&'a Uuid);

impl<'a> fmt::Display for HyphenatedRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.0.to_hyphenated_array()))
        }
    }
}

/// A simple format of Uuid which takes ownership of Uuid
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Simple(Uuid);

impl fmt::Display for Simple {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.0.to_simple_array()))
        }
    }
}

/// A simple format of Uuid which takes reference of Uuid
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SimpleRef<'a>(&'a Uuid);

impl<'a> fmt::Display for SimpleRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.0.to_simple_array()))
        }
    }
}

/// A urn format of Uuid which takes ownership of Uuid
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Urn(Uuid);

impl fmt::Display for Urn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.0.to_urn_array()))
        }
    }
}

/// A urn format of Uuid which takes reference of Uuid
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct UrnRef<'a>(&'a Uuid);

impl<'a> fmt::Display for UrnRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.write_str(from_utf8_unchecked(&self.0.to_urn_array()))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nil() {
        assert_eq!(Uuid::nil().to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_to_string() {
        assert_eq!(Uuid::NAMESPACE_DNS.to_string(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(Uuid::NAMESPACE_URL.to_string(), "6ba7b811-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(Uuid::NAMESPACE_OID.to_string(), "6ba7b812-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(Uuid::NAMESPACE_X500.to_string(), "6ba7b814-9dad-11d1-80b4-00c04fd430c8");
    }

    #[test]
    fn test_version() {
        assert_eq!(Uuid::NAMESPACE_DNS.version(), Version(1));
    }

    #[test]
    fn test_variant() {
        assert_eq!(Uuid::NAMESPACE_DNS.variant(), Variant::RFC4122);
    }

    #[test]
    fn test_format() {
        assert_eq!(Uuid::NAMESPACE_DNS.to_hyphenated().to_string(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(Uuid::NAMESPACE_DNS.to_hyphenated_ref().to_string(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8");

        assert_eq!(Uuid::NAMESPACE_DNS.to_simple().to_string(), "6ba7b8109dad11d180b400c04fd430c8");
        assert_eq!(Uuid::NAMESPACE_DNS.to_simple_ref().to_string(), "6ba7b8109dad11d180b400c04fd430c8");

        assert_eq!(Uuid::NAMESPACE_DNS.to_urn().to_string(), "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8");
        assert_eq!(Uuid::NAMESPACE_DNS.to_urn_ref().to_string(), "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    }

    static TESTS: &'static [(&'static str, Version, Variant, bool)] = &[
        ("f47ac10b-58cc-0372-8567-0e02b2c3d479", Version(0), Variant::RFC4122, true),
	("f47ac10b-58cc-1372-8567-0e02b2c3d479", Version(1), Variant::RFC4122, true),
	("f47ac10b-58cc-2372-8567-0e02b2c3d479", Version(2), Variant::RFC4122, true),
	("f47ac10b-58cc-3372-8567-0e02b2c3d479", Version(3), Variant::RFC4122, true),
	("f47ac10b-58cc-4372-8567-0e02b2c3d479", Version(4), Variant::RFC4122, true),
	("f47ac10b-58cc-5372-8567-0e02b2c3d479", Version(5), Variant::RFC4122, true),
	("f47ac10b-58cc-6372-8567-0e02b2c3d479", Version(6), Variant::RFC4122, true),
	("f47ac10b-58cc-7372-8567-0e02b2c3d479", Version(7), Variant::RFC4122, true),
	("f47ac10b-58cc-8372-8567-0e02b2c3d479", Version(8), Variant::RFC4122, true),
	("f47ac10b-58cc-9372-8567-0e02b2c3d479", Version(9), Variant::RFC4122, true),
	("f47ac10b-58cc-a372-8567-0e02b2c3d479", Version(10), Variant::RFC4122, true),
	("f47ac10b-58cc-b372-8567-0e02b2c3d479", Version(11), Variant::RFC4122, true),
	("f47ac10b-58cc-c372-8567-0e02b2c3d479", Version(12), Variant::RFC4122, true),
	("f47ac10b-58cc-d372-8567-0e02b2c3d479", Version(13), Variant::RFC4122, true),
	("f47ac10b-58cc-e372-8567-0e02b2c3d479", Version(14), Variant::RFC4122, true),
	("f47ac10b-58cc-f372-8567-0e02b2c3d479", Version(15), Variant::RFC4122, true),

	("urn:uuid:f47ac10b-58cc-4372-0567-0e02b2c3d479", Version(4), Variant::Reserved, true ),
	("URN:UUID:f47ac10b-58cc-4372-0567-0e02b2c3d479", Version(4), Variant::Reserved, true ),
	("f47ac10b-58cc-4372-0567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-1567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-2567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-3567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-4567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-5567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-6567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-7567-0e02b2c3d479", Version(4), Variant::Reserved, true),
	("f47ac10b-58cc-4372-8567-0e02b2c3d479", Version(4), Variant::RFC4122, true),
	("f47ac10b-58cc-4372-9567-0e02b2c3d479", Version(4), Variant::RFC4122, true),
	("f47ac10b-58cc-4372-a567-0e02b2c3d479", Version(4), Variant::RFC4122, true),
	("f47ac10b-58cc-4372-b567-0e02b2c3d479", Version(4), Variant::RFC4122, true),
	("f47ac10b-58cc-4372-c567-0e02b2c3d479", Version(4), Variant::Microsoft, true),
	("f47ac10b-58cc-4372-d567-0e02b2c3d479", Version(4), Variant::Microsoft, true),
	("f47ac10b-58cc-4372-e567-0e02b2c3d479", Version(4), Variant::Future, true),
	("f47ac10b-58cc-4372-f567-0e02b2c3d479", Version(4), Variant::Future, true),


	("f47ac10b158cc-5372-a567-0e02b2c3d479", Version(0), Variant::Invalid, false),
	("f47ac10b-58cc25372-a567-0e02b2c3d479", Version(0), Variant::Invalid, false),
	("f47ac10b-58cc-53723a567-0e02b2c3d479", Version(0), Variant::Invalid, false),
	("f47ac10b-58cc-5372-a56740e02b2c3d479", Version(0), Variant::Invalid, false),
	("f47ac10b-58cc-5372-a567-0e02-2c3d479", Version(0), Variant::Invalid, false),
	("g47ac10b-58cc-4372-a567-0e02b2c3d479", Version(0), Variant::Invalid, false),


	("{f47ac10b-58cc-0372-8567-0e02b2c3d479}", Version(0), Variant::RFC4122, true),
	("{f47ac10b-58cc-0372-8567-0e02b2c3d479", Version(0), Variant::Invalid, false),
	("f47ac10b-58cc-0372-8567-0e02b2c3d479}", Version(0), Variant::Invalid, false),

	("f47ac10b58cc037285670e02b2c3d479", Version(0), Variant::RFC4122, true),
	("f47ac10b58cc037285670e02b2c3d4790", Version(0), Variant::Invalid, false),
	("f47ac10b58cc037285670e02b2c3d47", Version(0), Variant::Invalid, false),
    ];

    #[test]
    fn test_from_str() {
        for &(ref s, ref ver, ref var, isuuid) in TESTS {
            let result = Uuid::from_str(s);
            if !isuuid {
                assert!(result.is_err());
            } else {
                let uuid = result.unwrap();
                assert_eq!(uuid.version(), *ver);
                assert_eq!(uuid.variant(), *var);
            }
        }
    }
}
