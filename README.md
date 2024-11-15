## UUID ![](https://github.com/awh6al/uuid-rs/workflows/uuid-rs/badge.svg)
A universally unique identifier (UUID) is a 128-bit number used to identify information in computer systems. When properly generated, UUIDs have an extremely low probability of duplication, making them ideal for distributed systems.

This crate provides a fast and compliant implementation of UUIDs based on:
 * [RFC 4122](http://tools.ietf.org/html/rfc4122) (UUID specification)
 * [DCE 1.1](https://pubs.opengroup.org/onlinepubs/9696989899/chap5.htm#tagcjh_08_02_01_01) (UUID implementation)

## Features
- Generate UUIDs (v4 random)
- Parse UUID strings
- Convert UUIDs to bytes and strings
- Zero-cost abstractions
- No unsafe code

## Usage Examples
```rust
use uuid_rs::{UUID, v4};

// Generate a random UUID
let id = v4!();
println!("{}", id); // e.g. "67e55044-10b1-426f-9247-bb680e5fe0c8"

// Parse a UUID string
let parsed = UUID::parse("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
assert_eq!(parsed.to_string(), "67e55044-10b1-426f-9247-bb680e5fe0c8");

// Get raw bytes
let bytes = id.as_bytes();
```

## Security Considerations
UUIDs should not be used for security purposes or as secret tokens. While UUIDs are unique, they are not cryptographically secure identifiers. For security-sensitive applications, use purpose-built cryptographic primitives instead.
