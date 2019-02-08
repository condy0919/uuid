//! The implementation for Version 1 UUIDs.

use super::*;
use rand::{self, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(non_upper_case_globals)]
const lillian: u64 = 2299160; // Julian day of 15 Oct 1582
#[allow(non_upper_case_globals)]
const unix: u64 = 2440587; // Julian day of 1 Jan 1970
#[allow(non_upper_case_globals)]
const epoch: u64 = unix - lillian;
#[allow(non_upper_case_globals)]
const g1582: u64 = epoch * 86400;
#[allow(non_upper_case_globals)]
const g1582ns100: u64 = g1582 * 1000000;

/// A stateful context for the v1 generator
#[derive(Default)]
pub struct Context {
    last_time: u64,
    clock_seq: u16,
}

/// A trait that abstracts over generation of Time and ClockSequence
pub trait TimeClockSequence {
    /// Returns a 64-bit Time and a 16-bit number that will be used as the
    /// "clock sequence" in the UUID. The number must be different if the time
    /// go backwards.
    fn gen(&mut self) -> (u64, u16);
}

impl Context {
    /// Creates a default context to help ensure uniqueness
    pub fn new() -> Self {
        Default::default()
    }
}

impl TimeClockSequence for Context {
    fn gen(&mut self) -> (u64, u16) {
        let since_the_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        if self.last_time == 0 {
            let mut rng = rand::thread_rng();
            let mut bs: [u8; 2] = Default::default();

            rng.fill_bytes(&mut bs);

            self.clock_seq = (((u16::from(bs[0]) << 8) | u16::from(bs[1])) & 0x3fff) | 0x8000; // Variant::RFC4122
        }

        let now = since_the_epoch.as_secs() * 10000000
            + since_the_epoch.subsec_nanos() as u64 / 100
            + g1582ns100;
        if now <= self.last_time {
            self.clock_seq = ((self.clock_seq + 1) & 0x3fff) | 0x8000; // Variant::RFC4122
        }
        self.last_time = now;

        (now, self.clock_seq)
    }
}

impl Uuid {
    /// Creates a new Version 1 UUID using a time value + clock sequence + NodeID
    ///
    /// This function is not guaranteed to produce monotonically increasing values
    /// however. There is a slight possibility that 2 successive equal time values
    /// could be supplied and the clock sequence wraps back over to 0.
    ///
    /// The possibility is 1.53e-5
    ///
    /// # Examples
    ///
    /// ```
    /// use yauuid::{Uuid, Node, Context};
    ///
    /// let mut ctx = Context::new();
    /// let node = Node::new("lo");
    /// let u = Uuid::new_v1(&mut ctx, node);
    /// ```
    pub fn new_v1<T: TimeClockSequence>(ctx: &mut T, node: Node) -> Uuid {
        let mut uuid: [u8; 16] = Default::default();

        let (now, seq) = ctx.gen();
        let time_low = (now & 0xffffffff) as u32;
        let time_mid = ((now >> 32) & 0xffff) as u16;
        let time_hi = ((now >> 48) & 0x0fff) as u16 | 0x1000; // Version 1
        uuid[0..4].copy_from_slice(&time_low.to_be_bytes());
        uuid[4..6].copy_from_slice(&time_mid.to_be_bytes());
        uuid[6..8].copy_from_slice(&time_hi.to_be_bytes());
        uuid[8..10].copy_from_slice(&seq.to_be_bytes());
        uuid[10..].copy_from_slice(&node.id());

        Uuid::from_bytes(uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let mut ctx = Context::new();
        let node = Node::new("lo");

        let u1 = Uuid::new_v1(&mut ctx, node);
        assert_eq!(u1.version(), Version(1));
        assert_eq!(u1.variant(), Variant::RFC4122);

        let u2 = Uuid::new_v1(&mut ctx, node);
        assert_eq!(u2.version(), Version(1));
        assert_eq!(u2.variant(), Variant::RFC4122);

        assert_ne!(u1, u2);
    }
}
