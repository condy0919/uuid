use super::*;
use md5::{Md5, Digest};

impl Uuid {
    /// Creates a Version 3 UUID by Md5 hashing a name from namespace and data.
    ///
    /// There are 4 namespaces available in this crate:
    ///
    /// * NAMESPACE_DNS
    /// * NAMESPACE_OID
    /// * NAMESPACE_URL
    /// * NAMESPACE_X500
    ///
    /// # Examples
    ///
    /// ```
    /// use yauuid::Uuid;
    ///
    /// let u = Uuid::new_v3(&Uuid::NAMESPACE_DNS, "python.org".as_bytes());
    /// ```
    pub fn new_v3(ns: &Uuid, data: &[u8]) -> Self {
        let mut result = Md5::new()
            .chain(ns.as_bytes())
            .chain(data)
            .result();

        result[6] = (result[6] & 0x0f) | (0x3 << 4); // version 3
        result[8] = (result[8] & 0x3f) | 0x80;       // RFC4122 variant

        let mut uuid: [u8; 16] = Default::default();
        uuid.copy_from_slice(&result[..]);
        Uuid::from_bytes(uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TESTS: &'static [(&'static Uuid, &'static str, &'static str)] = &[
        (
            &Uuid::NAMESPACE_DNS,
            "example.org",
            "04738bdf-b25a-3829-a801-b21a1d25095b",
        ),
        (
	    &Uuid::NAMESPACE_DNS,
	    "rust-lang.org",
	    "c6db027c-615c-3b4d-959e-1a917747ca5a",
	),
	(
	    &Uuid::NAMESPACE_DNS,
	    "42",
	    "5aab6e0c-b7d3-379c-92e3-2bfbb5572511",
	),
	(
	    &Uuid::NAMESPACE_DNS,
	    "lorem ipsum",
	    "4f8772e9-b59c-3cc9-91a9-5c823df27281",
	),
        (
            &Uuid::NAMESPACE_DNS,
            "python.org",
            "6fa459ea-ee8a-3ca4-894e-db77e160355e",
        ),
	(
	    &Uuid::NAMESPACE_URL,
	    "example.org",
	    "39682ca1-9168-3da2-a1bb-f4dbcde99bf9",
	),
	(
	    &Uuid::NAMESPACE_URL,
	    "rust-lang.org",
	    "7ed45aaf-e75b-3130-8e33-ee4d9253b19f",
	),
	(
	    &Uuid::NAMESPACE_URL,
	    "42",
	    "08998a0c-fcf4-34a9-b444-f2bfc15731dc",
	),
	(
	    &Uuid::NAMESPACE_URL,
	    "lorem ipsum",
	    "e55ad2e6-fb89-34e8-b012-c5dde3cd67f0",
	),
        (
	    &Uuid::NAMESPACE_OID,
	    "example.org",
	    "f14eec63-2812-3110-ad06-1625e5a4a5b2",
	),
	(
	    &Uuid::NAMESPACE_OID,
	    "rust-lang.org",
	    "6506a0ec-4d79-3e18-8c2b-f2b6b34f2b6d",
	),
	(
	    &Uuid::NAMESPACE_OID,
	    "42",
	    "ce6925a5-2cd7-327b-ab1c-4b375ac044e4",
	),
	(
	    &Uuid::NAMESPACE_OID,
	    "lorem ipsum",
	    "5dd8654f-76ba-3d47-bc2e-4d6d3a78cb09",
	),
	(
	    &Uuid::NAMESPACE_X500,
	    "example.org",
	    "64606f3f-bd63-363e-b946-fca13611b6f7",
	),
	(
	    &Uuid::NAMESPACE_X500,
	    "rust-lang.org",
	    "bcee7a9c-52f1-30c6-a3cc-8c72ba634990",
	),
	(
	    &Uuid::NAMESPACE_X500,
	    "42",
	    "c1073fa2-d4a6-3104-b21d-7a6bdcf39a23",
	),
        (
	    &Uuid::NAMESPACE_X500,
	    "lorem ipsum",
	    "02f09a3f-1624-3b1d-8409-44eff7708208",
	),
    ];

    #[test]
    fn test_new() {
        for &(ref ns, ref name, _) in TESTS {
            let uuid = Uuid::new_v3(*ns, name.as_bytes());
            assert_eq!(uuid.version(), Version(3));
            assert_eq!(uuid.variant(), Variant::RFC4122);
        }
    }

    #[test]
    fn test_to_string() {
        for &(ref ns, ref name, ref exp) in TESTS {
            let uuid = Uuid::new_v3(*ns, name.as_bytes());
            assert_eq!(uuid.to_string(), *exp);
        }
    }
}
