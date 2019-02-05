use std::str::FromStr;
use std::fmt;
use std::error;

pub mod v1;
pub mod v3;
pub mod v4;
pub mod v5;

mod util;
use util::xtob;


#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

#[derive(Debug, PartialEq)]
pub struct Version(u8);

#[derive(Debug, PartialEq)]
pub enum Variant {
    Invalid = 0,
    RFC4122 = 1,
    Reserved = 2,
    Microsoft = 3,
    Future = 4,
}

#[derive(Debug, Clone)]
pub struct InvalidUuid;

impl FromStr for Uuid {
    type Err = InvalidUuid;

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

impl Uuid {
    pub const NAMESPACE_DNS: Self = Self([0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    pub const NAMESPACE_URL: Self = Self([0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    pub const NAMESPACE_OID: Self = Self([0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);
    pub const NAMESPACE_X500: Self = Self([0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8]);

    pub fn nil() -> Self {
        Uuid([0; 16])
    }

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

    pub fn version(&self) -> Version {
        Version(self.0[6] >> 4)
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

    const NAME_SPACE_DNS: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const NAME_SPACE_DNS_WITH_URN: &str = "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const NAME_SPACE_DNS_WITH_BRACE: &str = "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}";
    const NAME_SPACE_DNS_WITHOUT_SLASH: &str = "6ba7b8109dad11d180b400c04fd430c8";

    const INVALID_UUID1: &str = "urn:uuid;6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const INVALID_UUID2: &str = "zba7b8109dad11d180b400c04fd430c8";
    const INVALID_UUID3: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8-hello";
    const INVALID_UUID4: &str = "6ba7b810+9dad-11d1-80b4-00c04fd430c8";
    const INVALID_UUID5: &str = "zba7b810-9dad-11d1-80b4-00c04fd430c8";

    #[test]
    fn test_from_str() {
        assert!(Uuid::from_str(NAME_SPACE_DNS).is_ok());
        assert!(Uuid::from_str(NAME_SPACE_DNS_WITH_URN).is_ok());
        assert!(Uuid::from_str(NAME_SPACE_DNS_WITH_BRACE).is_ok());
        assert!(Uuid::from_str(NAME_SPACE_DNS_WITHOUT_SLASH).is_ok());

        assert!(Uuid::from_str(INVALID_UUID1).is_err());
        assert!(Uuid::from_str(INVALID_UUID2).is_err());
        assert!(Uuid::from_str(INVALID_UUID3).is_err());
        assert!(Uuid::from_str(INVALID_UUID4).is_err());
        assert!(Uuid::from_str(INVALID_UUID5).is_err());
    }

    #[test]
    fn test_predefined_uuid() {
        assert_eq!(Uuid::NAMESPACE_DNS.to_string(), NAME_SPACE_DNS);
    }

    #[test]
    fn test_to_string() {
        assert_eq!(Uuid::from_str(NAME_SPACE_DNS).unwrap().to_string(), NAME_SPACE_DNS);
        assert_eq!(Uuid::from_str(NAME_SPACE_DNS_WITH_URN).unwrap().to_string(), NAME_SPACE_DNS);
        assert_eq!(Uuid::from_str(NAME_SPACE_DNS_WITH_BRACE).unwrap().to_string(), NAME_SPACE_DNS);
        assert_eq!(Uuid::from_str(NAME_SPACE_DNS_WITHOUT_SLASH).unwrap().to_string(), NAME_SPACE_DNS);
    }

    #[test]
    fn test_version() {
        assert_eq!(Uuid::from_str(NAME_SPACE_DNS).unwrap().version(), Version(1));
    }

    #[test]
    fn test_variant() {
        assert_eq!(Uuid::from_str(NAME_SPACE_DNS).unwrap().variant(), Variant::RFC4122);
    }
}
