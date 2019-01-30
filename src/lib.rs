use std::str::FromStr;
use std::string::ToString;

pub struct UUID([u8; 16]);

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
pub struct InvalidUUIDString;

impl FromStr for UUID {
    type Err = InvalidUUIDString;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut uuid: [u8; 16] = Default::default();

        let s = match s.len() {
            // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            36 => s,

            // urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            45 => {
                if (&s[..9]).to_lowercase() != "urn:uuid:" {
                    return Err(InvalidUUIDString);
                }
                &s[9..]
            },

            // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
            38 => &s[1..37],

            // xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            32 => {
                let bs = s.as_bytes();

                for i in 0..16 {
                    let (v, ok) = xtob(bs[2 * i], bs[2 * i + 1]);
                    if !ok {
                        return Err(InvalidUUIDString);
                    }
                    uuid[i] = v;
                }

                return Ok(UUID(uuid));
            },

            _ => return Err(InvalidUUIDString),
        };

        let bs = s.as_bytes();
        if char::from(bs[8]) != '-' || char::from(bs[13]) != '-' ||
            char::from(bs[18]) != '-' || char::from(bs[23]) != '-' {
            return Err(InvalidUUIDString);
        }
        for (i, val) in [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34].iter().enumerate() {
            let (v, ok) = xtob(bs[*val], bs[*val + 1]);
            if !ok {
                return Err(InvalidUUIDString);
            }
            uuid[i] = v;
        }
        Ok(UUID(uuid))
    }
}

impl ToString for UUID {
    fn to_string(&self) -> String {
        // TODO use snprintf
        format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
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

impl UUID {
    fn variant(&self) -> Variant {
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

    fn version(&self) -> Version {
        Version(self.0[6] >> 4)
    }
}

impl ToString for Variant {
    fn to_string(&self) -> String {
        let s = match self {
            Variant::Invalid => "Invalid",
            Variant::RFC4122 => "RFC4122",
            Variant::Reserved => "Reserved",
            Variant::Microsoft => "Microsoft",
            Variant::Future => "Future",
        };
        s.to_owned()
    }
}

impl ToString for Version {
    fn to_string(&self) -> String {
        format!("VERSION_{}", self.0)
    }
}

const XVALUES: [u8; 256] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0,    1,    2,    3,    4,    5,    6,    7,    8,    9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

fn xtob(a: u8, b: u8) -> (u8, bool) {
    let hi = XVALUES[a as usize];
    let lo = XVALUES[b as usize];
    ((hi << 4) | lo, hi != 255 && lo != 255)
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
        assert!(UUID::from_str(NAME_SPACE_DNS).is_ok());
        assert!(UUID::from_str(NAME_SPACE_DNS_WITH_URN).is_ok());
        assert!(UUID::from_str(NAME_SPACE_DNS_WITH_BRACE).is_ok());
        assert!(UUID::from_str(NAME_SPACE_DNS_WITHOUT_SLASH).is_ok());

        assert!(UUID::from_str(INVALID_UUID1).is_err());
        assert!(UUID::from_str(INVALID_UUID2).is_err());
        assert!(UUID::from_str(INVALID_UUID3).is_err());
        assert!(UUID::from_str(INVALID_UUID4).is_err());
        assert!(UUID::from_str(INVALID_UUID5).is_err());
    }

    #[test]
    fn test_to_string() {
        assert_eq!(UUID::from_str(NAME_SPACE_DNS).unwrap().to_string(), NAME_SPACE_DNS);
        assert_eq!(UUID::from_str(NAME_SPACE_DNS_WITH_URN).unwrap().to_string(), NAME_SPACE_DNS);
        assert_eq!(UUID::from_str(NAME_SPACE_DNS_WITH_BRACE).unwrap().to_string(), NAME_SPACE_DNS);
        assert_eq!(UUID::from_str(NAME_SPACE_DNS_WITHOUT_SLASH).unwrap().to_string(), NAME_SPACE_DNS);
    }

    #[test]
    fn test_version() {
        assert_eq!(UUID::from_str(NAME_SPACE_DNS).unwrap().version(), Version(1));
    }

    #[test]
    fn test_variant() {
        assert_eq!(UUID::from_str(NAME_SPACE_DNS).unwrap().variant(), Variant::RFC4122);
    }
}
