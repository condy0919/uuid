extern crate yauuid;

use yauuid::{Context, Node};
use yauuid::Uuid;

#[test]
fn test_uuid_v1() {
    let mut ctx = Context::new();
    let node = Node::new("lo");
    let uuid_v1_0 = Uuid::new_v1(&mut ctx, node);
    let uuid_v1_1 = Uuid::new_v1(&mut ctx, node);
    assert_ne!(uuid_v1_0, uuid_v1_1);
}

