#![feature(test)]
#![cfg(any(
    feature = "hash_md5",
    feauture = "hash_sha1",
    feauture = "random",
    feauture = "mac"
))]

extern crate test;
use test::Bencher;

use uuid_rs::{Domain, Version, UUID};

#[bench]
fn bench_v1(b: &mut Bencher) {
    b.iter(|| UUID::v1());
}

#[bench]
fn bench_v2(b: &mut Bencher) {
    b.iter(|| UUID::v2(Domain::PERSON));
}

#[bench]
fn bench_from_mac(b: &mut Bencher) {
    b.iter(|| UUID::from_mac(Version::TIME, [0x03, 0x2a, 0x35, 0x0d, 0x13, 0x80]));
}

#[bench]
fn bench_v3(b: &mut Bencher) {
    b.iter(|| UUID::v3("any", UUID::NAMESPACE_DNS));
}

#[bench]
fn bench_v4(b: &mut Bencher) {
    b.iter(|| UUID::v4());
}

#[bench]
fn bench_v5(b: &mut Bencher) {
    b.iter(|| UUID::v5("any", UUID::NAMESPACE_X500));
}
