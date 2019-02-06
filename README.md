# yauuid

The uuid crate generates and parse UUIDs based on [RFC 4122](http://tools.ietf.org/html/rfc4122)
and DCE 1.1: Authentication and Security Services.

## Usage

Add this to your `Cargo.toml`:

```toml
[denpendencies]
yauuid = "0.1"
```

and this to your crate root:

```rust
extern crate yauuid;
```

## Examples

To parse a simple UUID, then print the version and variant:

```rust
extern crate yauuid;

use yauuid::Uuid;
use std::str::FromStr;

fn main() {
    let u = Uuid::from_str("urn:uuid:123e4567-e89b-12d3-a456-426655440000").unwrap();
    println!("version = {}, variant = {}", u.version(), u.variant());
}
```

The library supports 5 versions of UUID:

Name    | Version
--------|---------
Mac     | Version 1: Mac address
Dce     | Version 2: DCE Security
Md5     | Version 3: Md5 hash
Random  | Version 4: Random
Sha1    | Version 5: Sha1 hash

## Benchmarks

Lower is better.

benchmark    | uuid-rs (ns) | yauuid (ns)
-------------|--------------|-------------
parse\_str   | 70.240       | **33.176**
to\_string   | 107.48       | **75.387**
new\_v1      | 6.1016       | 6.1530
new\_v3      | 211.16       | 174.33
new\_v4      | 29.946       | 30.557
new\_v5      | 209.24       | 212.94

The `parse_str` benchmark is 2x, and `to_string` is 1.5x.

The `new_v1` costs are similar, but `yauuid`'s version is easy to use.
No time parameters required. It has been included in `yauuid::Context` struct.

The `new_v3`, `new_v4`, `new_v5` benchmark `md5`, `RNG`, `sha1` performance instead.

Run `cargo bench` to get the benchmark result.

See `benches/bench.rs` for benchmark cases detail.


## References

 - [RFC 4122](http://tools.ietf.org/html/rfc4122)

 - [Universally unique identifier](https://en.wikipedia.org/wiki/Universally_unique_identifier)
