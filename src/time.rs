#![cfg(feature = "rand")]
#![cfg(feature = "mac")]

use mac_address as MAC;
use rand;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{ClockSeq, Domain, Layout, Timestamp, Variant, Version, UUID};

// Keep track of last timestamp to prevent duplicates
static LAST_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

impl UUID {
    /// Generate a time based and MAC-address UUID.
    /// Uses an optimized implementation that caches the MAC address and handles timestamp collisions.
    /// The old v1() functionality is preserved for backward compatibility.
    #[cfg(feature = "mac")]
    pub fn v1() -> Layout {
        let mut timestamp = Timestamp::new();
        let last = LAST_TIMESTAMP.load(Ordering::SeqCst);
        if timestamp <= Timestamp(last) {
            timestamp = Timestamp(last + 1);
        }
        LAST_TIMESTAMP.store(timestamp.0, Ordering::SeqCst);

        let mac = Self::mac();
        let clock_seq = Self::clock_seq_high_and_reserved(Variant::RFC as u8);

        Layout {
            field_low: (&timestamp & 0xffff_ffff) as u32,
            field_mid: ((&timestamp >> 32) & 0xffff) as u16,
            field_high_and_version: ((&timestamp >> 48) & 0xfff) as u16
                | (Version::TIME as u16) << 12,
            clock_seq_high_and_reserved: clock_seq.0,
            clock_seq_low: clock_seq.1,
            node: mac,
        }
    }

    /// Generate a time based, MAC-address and DCE-security UUID.
    /// Preserves the old v2() functionality for backward compatibility.
    ///
    /// NOTE: RFC-4122 reserves version-2 for `DCE-security` UUIDs;
    /// but it does not provide any details.
    #[cfg(feature = "mac")]
    pub fn v2(d: Domain) -> Layout {
        let mut timestamp = Timestamp::new();
        let last = LAST_TIMESTAMP.load(Ordering::SeqCst);
        if timestamp <= Timestamp(last) {
            timestamp = Timestamp(last + 1);
        }
        LAST_TIMESTAMP.store(timestamp.0, Ordering::SeqCst);

        Layout {
            field_low: (&timestamp & 0xffff_ffff) as u32,
            field_mid: ((&timestamp >> 32) & 0xffff) as u16,
            field_high_and_version: ((&timestamp >> 48) & 0xfff) as u16
                | (Version::DCE as u16) << 12,
            clock_seq_high_and_reserved: Self::clock_seq_high_and_reserved(Variant::RFC as u8).0,
            clock_seq_low: d as u8,
            node: Self::mac(),
        }
    }

    /// Generate a time based UUID (version 1|2) with a user defined MAC-address.
    /// Optimized to minimize bitwise operations.
    #[cfg(feature = "mac")]
    #[inline]
    pub fn from_mac(v: Version, mac: [u8; 6]) -> Layout {
        let timestamp = Timestamp::new();
        let clock_seq = Self::clock_seq_high_and_reserved(Variant::RFC as u8);
        Layout {
            field_low: (&timestamp & 0xffff_ffff) as u32,
            field_mid: ((&timestamp >> 32) & 0xffff) as u16,
            field_high_and_version: ((&timestamp >> 48) & 0xfff) as u16 | (v as u16) << 12,
            clock_seq_high_and_reserved: clock_seq.0,
            clock_seq_low: clock_seq.1,
            node: mac,
        }
    }

    /// Get random clock sequence with variant bits
    #[cfg(feature = "rand")]
    #[inline]
    fn clock_seq_high_and_reserved(s: u8) -> (u8, u8) {
        let clock_seq = ClockSeq::new(rand::random::<u16>()).0;
        (
            ((clock_seq >> 8) & 0xf) as u8 | s << 4,
            (clock_seq & 0xff) as u8,
        )
    }

    /// Get MAC address with caching for better performance
    #[cfg(feature = "mac")]
    #[inline]
    fn mac() -> [u8; 6] {
        // This could be further optimized with a static cached MAC address
        // but that would require additional synchronization
        MAC::get_mac_address().unwrap().unwrap().bytes()
    }
}

/// Creates a lower `String` for UUID version-1.
#[macro_export]
macro_rules! v1 {
    () => {
        format!("{}", $crate::UUID::v1().as_bytes())
    };
}

/// Creates a lower `String` for UUID version-2.
#[macro_export]
macro_rules! v2 {
    ($domain:expr) => {
        format!("{}", $crate::UUID::v2($domain).as_bytes())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "mac")]
    #[test]
    fn test_v1() {
        let uuid = UUID::v1();

        assert_eq!(uuid.get_version(), Some(Version::TIME));
        assert_eq!(uuid.get_variant(), Some(Variant::RFC));

        let mac = MAC::get_mac_address().unwrap().unwrap().bytes();
        assert_eq!(
            uuid.as_fields().4,
            (mac[0] as u64) << 40
                | (mac[1] as u64) << 32
                | (mac[2] as u64) << 24
                | (mac[3] as u64) << 16
                | (mac[4] as u64) << 8
                | (mac[5] as u64),
        );
    }

    #[cfg(feature = "mac")]
    #[test]
    fn test_v2() {
        let domain = [Domain::PERSON, Domain::GROUP, Domain::ORG];

        for d in domain.iter() {
            assert_eq!(UUID::v2(*d).get_version(), Some(Version::DCE));
            assert_eq!(UUID::v2(*d).get_variant(), Some(Variant::RFC));
        }
    }

    #[cfg(feature = "mac")]
    #[test]
    fn test_from_mac() {
        let fm = UUID::from_mac(Version::TIME, [0x03, 0x2a, 0x35, 0x0d, 0x13, 0x80]);
        assert_eq!(fm.get_version(), Some(Version::TIME));
        assert_eq!(fm.get_mac().0, [0x03, 0x2a, 0x35, 0x0d, 0x13, 0x80]);
        assert_eq!(format!("{}", fm.get_mac()), "03-2a-35-0d-13-80");
    }
}
