use super::*;
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

pub struct Context {
    last_time: u64,
    clock_seq: u64,
}

pub trait TimeClockSequence {
    fn gen(&mut self) -> (u64, u64);
}

impl Context {
    pub fn new() -> Self {
        Context {
            last_time: 0,
            clock_seq: 0,
        }
    }
}

impl TimeClockSequence for Context {
    fn gen(&mut self) -> (u64, u64) {
        let since_the_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let now =
            since_the_epoch.as_secs() * 10000000 + since_the_epoch.subsec_nanos() as u64 / 100 + g1582ns100;
        if now <= self.last_time {
            self.clock_seq = ((self.clock_seq + 1) & 0x3fff) | 0x8000; // Variant::RFC4122
        }
        self.last_time = now;

        (now, self.clock_seq)
    }
}

impl Uuid {
    pub fn new_v1<T: TimeClockSequence>(ctx: &mut T, node: Node) -> Uuid {
        let mut uuid: [u8; 16] = Default::default();

        let (now, seq) = ctx.gen();
        let time_low = (now & 0xffffffff) as u32;
        let time_mid = ((now >> 32) & 0xffff) as u16;
        let time_hi = ((now >> 48) & 0x0fff) as u16 | 0x1000; // Version 1
        uuid[0..4].copy_from_slice(&time_low.to_be_bytes());
        uuid[4..6].copy_from_slice(&time_mid.to_be_bytes());
        uuid[6..8].copy_from_slice(&time_hi.to_be_bytes());
        uuid[8..10].copy_from_slice(&(seq as u16).to_be_bytes());
        uuid[10..].copy_from_slice(&node.id());

        Uuid(uuid)
    }
}
