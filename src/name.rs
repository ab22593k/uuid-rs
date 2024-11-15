#![cfg(feature = "hmd5")]
#![cfg(feature = "hsha1")]

use md5;
use sha1_smol::Sha1;

use crate::{Layout, Variant, Version, UUID};

impl UUID {
    /// Generate a UUID by hashing a namespace identifier and name uses MD5.
    #[cfg(feature = "hmd5")]
    pub fn v3(any: &str, namespace: UUID) -> Layout {
        let hash = md5::compute(Self::data(any, namespace)).0;
        Layout {
            field_low: ((hash[0] as u32) << 24)
                | (hash[1] as u32) << 16
                | (hash[2] as u32) << 8
                | hash[3] as u32,
            field_mid: (hash[4] as u16) << 8 | (hash[5] as u16),
            field_high_and_version: ((hash[6] as u16) << 8 | (hash[7] as u16)) & 0xfff
                | (Version::MD5 as u16) << 12,
            clock_seq_high_and_reserved: (hash[8] & 0xf) | (Variant::RFC as u8) << 4,
            clock_seq_low: hash[9] as u8,
            node: [hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]],
        }
    }

    /// Generate a UUID by hashing a namespace identifier and name uses SHA1.
    #[cfg(feature = "hsha1")]
    pub fn v5(any: &str, namespace: UUID) -> Layout {
        let hash = Sha1::from(Self::data(any, namespace)).digest().bytes();
        Layout {
            field_low: ((hash[0] as u32) << 24)
                | (hash[1] as u32) << 16
                | (hash[2] as u32) << 8
                | hash[3] as u32,
            field_mid: (hash[4] as u16) << 8 | (hash[5] as u16),
            field_high_and_version: ((hash[6] as u16) << 8 | (hash[7] as u16)) & 0xfff
                | (Version::SHA1 as u16) << 12,
            clock_seq_high_and_reserved: (hash[8] & 0xf) | (Variant::RFC as u8) << 4,
            clock_seq_low: hash[9] as u8,
            node: [hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]],
        }
    }

    fn data(any: &str, namespace: UUID) -> String {
        format!("{}", namespace) + any
    }
}

/// Creates a lower `String` for UUID version-3.
#[macro_export]
macro_rules! v3 {
    ($any:expr, $namespace:expr) => {
        format!("{}", $crate::UUID::v3($any, $namespace).as_bytes())
    };
}

/// Creates a lower `String` for UUID version-5.
#[macro_export]
macro_rules! v5 {
    ($any:expr, $namespace:expr) => {
        format!("{}", $crate::UUID::v5($any, $namespace).as_bytes())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NAMESPACES: [UUID; 4] = [
        UUID::NAMESPACE_DNS,
        UUID::NAMESPACE_OID,
        UUID::NAMESPACE_URL,
        UUID::NAMESPACE_X500,
    ];

    const TEST_STRINGS: [&str; 3] = ["test", "example", "sample"];

    #[cfg(feature = "hmd5")]
    #[test]
    fn test_v3_basic() {
        for &namespace in &TEST_NAMESPACES {
            let uuid = UUID::v3("any", namespace);
            assert_eq!(uuid.get_version(), Some(Version::MD5));
            assert_eq!(uuid.get_variant(), Some(Variant::RFC));
        }
    }

    #[cfg(feature = "hmd5")]
    #[test]
    fn test_v3_deterministic() {
        for &namespace in &TEST_NAMESPACES {
            for &test_str in &TEST_STRINGS {
                let uuid1 = UUID::v3(test_str, namespace);
                let uuid2 = UUID::v3(test_str, namespace);
                assert_eq!(uuid1, uuid2, "v3 UUIDs should be deterministic");
            }
        }
    }

    #[cfg(feature = "hsha1")]
    #[test]
    fn test_v5_basic() {
        for &namespace in &TEST_NAMESPACES {
            let uuid = UUID::v5("any", namespace);
            assert_eq!(uuid.get_version(), Some(Version::SHA1));
            assert_eq!(uuid.get_variant(), Some(Variant::RFC));
        }
    }

    #[cfg(feature = "hsha1")]
    #[test]
    fn test_v5_deterministic() {
        for &namespace in &TEST_NAMESPACES {
            for &test_str in &TEST_STRINGS {
                let uuid1 = UUID::v5(test_str, namespace);
                let uuid2 = UUID::v5(test_str, namespace);
                assert_eq!(uuid1, uuid2, "v5 UUIDs should be deterministic");
            }
        }
    }

    #[cfg(all(feature = "hmd5", feature = "hsha1"))]
    #[test]
    fn test_v3_v5_different() {
        for &namespace in &TEST_NAMESPACES {
            for &test_str in &TEST_STRINGS {
                let v3_uuid = UUID::v3(test_str, namespace);
                let v5_uuid = UUID::v5(test_str, namespace);
                assert_ne!(v3_uuid, v5_uuid, "v3 and v5 UUIDs should differ");
            }
        }
    }
}
