//! NodeID represent a MAC address.

use std::convert::From;
use std::fs;
use std::path::Path;
use std::fmt;
use std::str::from_utf8_unchecked;

#[path = "util.rs"]
mod util;
use util::xtob;

#[path = "macros.rs"]
#[macro_use]
mod macros;

/// An IEEE 802 MAC address
#[derive(Debug, Clone, Copy)]
pub struct Node([u8; 6]);

impl From<[u8; 6]> for Node {
    fn from(xs: [u8; 6]) -> Self {
        Node(xs)
    }
}

impl Node {
    /// Creates a node with specified interface name
    #[cfg(target_os = "linux")]
    pub fn new(interface: &str) -> Self {
        let dir = "/sys/class/net";
        let mut node: [u8; 6] = Default::default();

        // aa:bb:cc:dd:ee:ff
        let content = fs::read_to_string(Path::new(dir).join(interface).join("address"))
            .unwrap_or("00:00:00:00:00:00".to_owned());

        let bs = content.as_bytes();
        for (idx, &x) in [0, 3, 6, 9, 12, 15].iter().enumerate() {
            node[idx] = xtob(bs[x], bs[x + 1]).unwrap_or_default();
        }

        Node(node)
    }

    pub fn id(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let xs = self.0;

        let mut bs: [u8; 17] = [b':'; 17];
        bytes_format!(bs, xs, 0, 0, 1,
                                 3, 4,
                                 6, 7,
                                 9, 10,
                                 12, 13,
                                 15, 16);

        unsafe {
            f.write_str(from_utf8_unchecked(&bs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_lo_nodeid() {
        assert_eq!(Node::new("lo").id(), [0; 6]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_to_string() {
        let node = Node::new("lo");

        assert_eq!(node.to_string(), "00:00:00:00:00:00");
    }
}
