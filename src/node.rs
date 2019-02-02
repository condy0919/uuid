use std::convert::From;
use std::fs;
use std::path::Path;
use std::fmt;

use crate::util::xtob;

pub struct Node([u8; 6]);

impl From<[u8; 6]> for Node {
    fn from(xs: [u8; 6]) -> Self {
        Node(xs)
    }
}

impl Node {
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

    pub fn id(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let xs = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                   xs[0], xs[1], xs[2], xs[3], xs[4], xs[5])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_lo_nodeid() {
        assert_eq!(Node::new("lo").id(), [0, 0, 0, 0, 0, 0]);
    }
}
