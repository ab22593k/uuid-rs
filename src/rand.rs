#![cfg(feature = "random")]

use crate::{Layout, Variant, Version, UUID};
use rand;

impl UUID {
    /// Generate a UUID from truly random numbers.
    pub fn v4() -> Layout {
        let rng = rand::random::<u128>();
        let rand = rng.to_be_bytes();
        Layout {
            field_low: ((rand[0] as u32) << 24)
                | (rand[1] as u32) << 16
                | (rand[2] as u32) << 8
                | rand[3] as u32,
            field_mid: (rand[4] as u16) << 8 | (rand[5] as u16),
            field_high_and_version: ((rand[6] as u16) << 8 | (rand[7] as u16)) & 0xfff
                | (Version::RAND as u16) << 12,
            clock_seq_high_and_reserved: (rand[8] & 0xf) | (Variant::RFC as u8) << 4,
            clock_seq_low: rand[9] as u8,
            node: [rand[10], rand[11], rand[12], rand[13], rand[14], rand[15]],
        }
    }
}

/// Creates a lower `String` for UUID version-4.
#[macro_export]
macro_rules! v4 {
    () => {
        format!("{}", $crate::UUID::v4().as_bytes())
    };
    (expr:lower) => {
        format!("{}", $crate::UUID::v4().as_bytes().to_lower())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4() {
        let uuid = UUID::v4();
        assert_eq!(uuid.get_version(), Some(Version::RAND));
        assert_eq!(uuid.get_variant(), Some(Variant::RFC));
    }
}
