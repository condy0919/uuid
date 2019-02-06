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

use std::str::FromStr;
use std::fmt;
use std::error;
use std::default;

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
pub struct Version(u8);

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
        write!(f, "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                self.0[0],
                self.0[1],
                self.0[2],
                self.0[3],
                self.0[4],
                self.0[5],
                self.0[6],
                self.0[7],
                self.0[8],
                self.0[9],
                self.0[10],
                self.0[11],
                self.0[12],
                self.0[13],
                self.0[14],
                self.0[15])
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
        let s = match self {
            Variant::Invalid => "Invalid",
            Variant::RFC4122 => "RFC4122",
            Variant::Reserved => "Reserved",
            Variant::Microsoft => "Microsoft",
            Variant::Future => "Future",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VERSION_{}", self.0)
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
