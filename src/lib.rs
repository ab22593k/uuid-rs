//! `uuid-rs` implements Universally Unique IDentifiers (UUIDs) according to
//! [RFC 4122](https://tools.ietf.org/html/rfc4122). UUIDs are 128-bit numbers
//! that can be used to uniquely identify resources in distributed systems. Multiple
//! UUID versions are supported, including timestamp-based (v1), DCE Security (v2),
//! MD5 hash-based (v3), random (v4) and SHA-1 hash-based (v5) variants.

#![doc(html_root_url = "https://docs.rs/uuid-rs")]

pub mod name;
pub mod rand;
pub mod time;

use core::fmt;
use core::sync::atomic;
use std::time::SystemTime;

/// Is 100-ns ticks between UNIX and UTC epochs.
pub const UTC_EPOCH: u64 = 0x01B2_1DD2_1381_4000;

/// The UUID format is 16 octets.
#[derive(Debug, PartialEq)]
pub struct Layout {
    /// The low field of the Timestamp.
    pub field_low: u32,
    /// The mid field of the Timestamp.
    pub field_mid: u16,
    /// The high field of the Timestamp multiplexed with the version number.
    pub field_high_and_version: u16,
    /// The high field of the ClockSeq multiplexed with the variant.
    pub clock_seq_high_and_reserved: u8,
    /// The low field of the ClockSeq.
    pub clock_seq_low: u8,
    /// IEEE 802 MAC address.
    pub node: [u8; 6],
}

impl Layout {
    /// Returns the five field values of the UUID in big-endian order.
    pub fn as_fields(&self) -> (u32, u16, u16, u16, u64) {
        (
            self.field_low,
            self.field_mid,
            self.field_high_and_version,
            ((self.clock_seq_high_and_reserved as u16) << 8) | self.clock_seq_low as u16,
            (self.node[0] as u64) << 40
                | (self.node[1] as u64) << 32
                | (self.node[2] as u64) << 24
                | (self.node[3] as u64) << 16
                | (self.node[4] as u64) << 8
                | (self.node[5] as u64),
        )
    }

    /// Returns a byte slice of this UUID content.
    pub fn as_bytes(&self) -> UUID {
        UUID([
            self.field_low.to_be_bytes()[0],
            self.field_low.to_be_bytes()[1],
            self.field_low.to_be_bytes()[2],
            self.field_low.to_be_bytes()[3],
            self.field_mid.to_be_bytes()[0],
            self.field_mid.to_be_bytes()[1],
            self.field_high_and_version.to_be_bytes()[0],
            self.field_high_and_version.to_be_bytes()[1],
            self.clock_seq_high_and_reserved,
            self.clock_seq_low,
            self.node[0],
            self.node[1],
            self.node[2],
            self.node[3],
            self.node[4],
            self.node[5],
        ])
    }

    /// Get the version of the current generated UUID.
    pub fn get_version(&self) -> Option<Version> {
        match (self.field_high_and_version >> 12) & 0xf {
            0x01 => Some(Version::TIME),
            0x02 => Some(Version::DCE),
            0x03 => Some(Version::MD5),
            0x04 => Some(Version::RAND),
            0x05 => Some(Version::SHA1),
            _ => None,
        }
    }

    /// Get the variant field of the current generated UUID.
    pub fn get_variant(&self) -> Option<Variant> {
        match (self.clock_seq_high_and_reserved >> 4) & 0xf {
            0x00 => Some(Variant::NCS),
            0x01 => Some(Variant::RFC),
            0x02 => Some(Variant::MS),
            0x03 => Some(Variant::FUT),
            _ => None,
        }
    }

    /// Get timestamp where UUID generated in.
    pub fn get_time(&self) -> u64 {
        let t = ((self.field_high_and_version) as u64) << 48
            | (self.field_mid as u64) << 32
            | self.field_low as u64;

        t.checked_sub(UTC_EPOCH).unwrap()
    }

    /// Get the MAC-address where UUID generated with.
    pub fn get_mac(&self) -> Node {
        Node(self.node)
    }
}

/// Domain is security-domain-relative name.
#[derive(Debug, Copy, Clone)]
pub enum Domain {
    PERSON = 0,
    GROUP,
    ORG,
}

/// Variant is a type field determines the layout of the UUID.
#[derive(Debug, Eq, PartialEq)]
pub enum Variant {
    /// Reserved, NCS backward compatibility.
    NCS = 0,
    /// The variant specified in rfc4122 document.
    RFC,
    /// Reserved, Microsoft Corporation backward compatibility.
    MS,
    /// Reserved for future definition.
    FUT,
}

/// Version represents the type of UUID, and is in the most significant 4 bits of the Timestamp.
#[derive(Debug, Eq, PartialEq)]
pub enum Version {
    /// The time-based version specified in this document.
    TIME = 1,
    /// DCE Security version, with embedded POSIX UIDs.
    DCE,
    /// The name-based version specified in rfc4122 document that uses MD5 hashing.
    MD5,
    /// The randomly or pseudo-randomly generated version specified in rfc4122 document.
    RAND,
    /// The name-based version specified in rfc4122 document that uses SHA-1 hashing.
    SHA1,
}

/// Represented by Coordinated Universal Time (UTC)
/// as a count of 100-ns intervals from the system-time.
#[derive(Debug, Eq, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Default for Timestamp {
    fn default() -> Self {
        Self::new()
    }
}

impl Timestamp {
    /// Generate UTC timestamp.
    pub fn new() -> Self {
        let since_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        // 100-ns intervals since Unix epoch
        let intervals = since_unix.as_nanos() / 100;

        // Add UTC epoch offset
        let utc = intervals + UTC_EPOCH as u128;

        // Only take lower 60 bits per RFC 4122
        Self((utc & 0x0fff_ffff_ffff_ffff) as u64)
    }
}

use std::ops::{BitAnd, Shr};

impl BitAnd<u64> for Timestamp {
    type Output = u64;

    fn bitand(self, rhs: u64) -> Self::Output {
        self.0 & rhs
    }
}

impl BitAnd<u64> for &Timestamp {
    type Output = u64;

    fn bitand(self, rhs: u64) -> Self::Output {
        self.0 & rhs
    }
}

impl Shr<u32> for Timestamp {
    type Output = u64;

    fn shr(self, rhs: u32) -> Self::Output {
        self.0 >> rhs
    }
}

impl Shr<u32> for &Timestamp {
    type Output = u64;

    fn shr(self, rhs: u32) -> Self::Output {
        self.0 >> rhs
    }
}

/// Is a 128-bit number used to identify information in computer systems.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct UUID([u8; 16]);

impl UUID {
    /// UUID namespace for domain name system (DNS).
    pub const NAMESPACE_DNS: Self = UUID([
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]);

    /// UUID namespace for ISO object identifiers (OIDs).
    pub const NAMESPACE_OID: Self = UUID([
        0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]);

    /// UUID namespace for uniform resource locators (URLs).
    pub const NAMESPACE_URL: Self = UUID([
        0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]);

    /// UUID namespace for X.500 distinguished names (DNs).
    pub const NAMESPACE_X500: Self = UUID([
        0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]);
}

impl fmt::Display for UUID {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5],
            self.0[6],
            self.0[7],
            self.0[8],
            self.0[9],
            self.0[10],
            self.0[11],
            self.0[12],
            self.0[13],
            self.0[14],
            self.0[15],
        )
    }
}

/// The clock sequence is used to help avoid duplicates that could arise when the
/// clock is set backwards in time or if the node ID changes. According to RFC 4122,
/// it is initialized with a random value when the UUID generator starts up.
#[derive(Debug)]
pub struct ClockSeq(pub u16);

impl std::ops::Deref for ClockSeq {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ClockSeq {
    /// Generate new clock sequence value, initialized with random bits and
    /// monotonically incrementing thereafter to prevent collisions.
    pub fn new(random_bits: u16) -> Self {
        // According to RFC 4122 Section 4.2.1:
        // "For UUID version 1, the clock sequence is used to help avoid
        // duplicates that could arise when the clock is set backwards in time
        // or if the node ID changes."

        // Only use 14 bits per spec, clear the variant bits
        let initial = random_bits & 0x3fff;
        Self(atomic::AtomicU16::new(initial).fetch_add(1, atomic::Ordering::AcqRel))
    }
}

/// The clock sequence is used to help avoid duplicates that could arise
/// when the clock is set backwards in time or if the node ID changes.
pub struct Node([u8; 6]);

impl fmt::Display for Node {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    fn is_valid(s: &str) -> bool {
        let regex = Regex::new(
            r"^(?i)(urn:uuid:)?[0-9a-f]{8}\-[0-9a-f]{4}\-[0-5]{1}[0-9a-f]{3}\-[0-9a-f]{4}\-[0-9a-f]{12}$",
        );
        regex.unwrap().is_match(s)
    }

    #[test]
    fn test_node_format() {
        let node = Node([00, 42, 53, 13, 19, 128]);

        assert_eq!(format!("{}", node), "00-2a-35-0d-13-80");
        assert_eq!(format!("{}", node).to_uppercase(), "00-2A-35-0D-13-80")
    }

    #[test]
    fn test_is_valid_uuid() {
        let uuid_strings = [
            "550e8400-e29b-41d4-a716-446655440000", // Example v4 UUID
            "d9428888-122b-11e1-b85c-61cd3cbb3210", // Example v1 UUID
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8", // NAMESPACE_URL constant
            "6ba7b814-9dad-11d1-80b4-00c04fd430c8", // NAMESPACE_X500 constant
        ];

        for id in uuid_strings.iter() {
            assert!(is_valid(id));
            assert!(is_valid(&id.to_uppercase()));
        }
    }
}
