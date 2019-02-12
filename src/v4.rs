//! The implementation for Version 4 UUIDs which produces a random UUID.

use super::*;
use rand::{self, RngCore};

impl Uuid {
    /// Creates a Version 4 UUID by randomizing
    ///
    /// This crate uses the [`rand`] crate as default RNG.
    ///
    /// # Examples
    ///
    /// ```
    /// use yauuid::Uuid;
    ///
    /// let u = Uuid::new_v4();
    /// ```
    ///
    /// [`rand`]: https://crates.io/crates/rand
    pub fn new_v4() -> Self {
        let mut rng = rand::thread_rng();
        let mut bs: [u8; 16] = Default::default();

        rng.fill_bytes(&mut bs);

        bs[6] = (bs[6] & 0x0f) | 0x40; // Version 4
        bs[8] = (bs[8] & 0x3f) | 0x80; // Variant RFC4122

        Uuid::from_bytes(bs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let uuid = Uuid::new_v4();

        assert_eq!(uuid.version(), Version(4));
        assert_eq!(uuid.variant(), Variant::RFC4122);
    }
}
