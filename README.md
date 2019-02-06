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

## References

 - [RFC 4122](http://tools.ietf.org/html/rfc4122)

 - [Universally unique identifier](https://en.wikipedia.org/wiki/Universally_unique_identifier)
