//! The implementation for Version 2 UUIDs which is based on Version 1 UUID.

use super::*;
use libc;

pub enum Domain {
    Person = 0,
    Group = 1,
    Org = 2,
}

impl Uuid {
    /// Creates a new Version 2 UUID based on a Version 1 UUID + domain name + id
    ///
    /// The domain may be either of Person, Group and Organization.
    ///
    /// The id may be PID, UID or GID.
    ///
    /// # Examples
    ///
    /// ```
    /// use yauuid::{Uuid, Node, Context};
    /// use yauuid::Domain;
    ///
    /// let mut ctx = Context::new();
    /// let node = Node::new("lo");
    ///
    /// let u1 = Uuid::new_v1(&mut ctx, node);
    ///
    /// let u = Uuid::new_v2(&u1, Domain::Person, 42);
    /// ```
    pub fn new_v2(uuid: &Uuid, domain: Domain, id: u32) -> Self {
        assert_eq!(uuid.version(), Version(1));

        let mut bs = uuid.as_bytes();
        bs[6] = (bs[6] & 0x0f) | (0x2 << 4); // version 2
        bs[9] = domain as u8;
        bs[0..4].copy_from_slice(&id.to_be_bytes());

        Uuid::from_bytes(bs)
    }

    /// Creates a Version 2 Person category UUID
    pub fn new_v2_person(uuid: &Uuid) -> Self {
        let uid = unsafe { libc::getuid() };
        Self::new_v2(uuid, Domain::Person, uid)
    }

    /// Creates a Version 2 Group category UUID
    pub fn new_v2_group(uuid: &Uuid) -> Self {
        let gid = unsafe { libc::getgid() };
        Self::new_v2(uuid, Domain::Group, gid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let mut cntx = Context::new();
        let node = Node::new("lo");

        let u_v1 = Uuid::new_v1(&mut cntx, node);

        let u = Uuid::new_v2(&u_v1, Domain::Person, 12345678);
        assert_eq!(u.version(), Version(2));
        assert_eq!(u.as_bytes()[0..4], 12345678u32.to_be_bytes());
    }
}
