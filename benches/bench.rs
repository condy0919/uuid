#[macro_use]
extern crate criterion;
extern crate yauuid;
extern crate uuid;

use criterion::Criterion;
use yauuid::Uuid;
use std::str::FromStr;


const BENCHMARK_STRING: &str = "f47ac10b-58cc-0372-8567-0e02b2c3d479";

// from_str benchmark group
fn benchmark_yauuid_from_str(c: &mut Criterion) {
    c.bench_function("yauuid: from_str", |b| {
        b.iter(|| assert!(Uuid::from_str(BENCHMARK_STRING).is_ok()))
    });
}

fn benchmark_uuid_from_str(c: &mut Criterion) {
    c.bench_function("uuid: parse_str", |b| {
        b.iter(|| assert!(uuid::Uuid::parse_str(BENCHMARK_STRING).is_ok()))
    });
}

// to_string benchmark group
fn benchmark_yauuid_to_string(c: &mut Criterion) {
    c.bench_function("yauuid: to_string", |b| {
        b.iter(|| {
            let nil = Uuid::nil();
            assert_eq!(nil.to_string(), "00000000-0000-0000-0000-000000000000");
        })
    });
}

fn benchmark_uuid_to_string(c: &mut Criterion) {
    c.bench_function("uuid: to_string", |b| {
        b.iter(|| {
            let nil = uuid::Uuid::nil();
            assert_eq!(nil.to_string(), "00000000-0000-0000-0000-000000000000");
        })
    });
}

// new_v1 benchmark group
fn benchmark_yauuid_new_v1(c: &mut Criterion) {
    c.bench_function("yauuid: new_v1", |b| {
        b.iter(|| {
            let mut ctx = yauuid::Context::new();
            let node = yauuid::Node::new("lo");

            let u = Uuid::new_v1(&mut ctx, &node);
            assert_eq!(u.version(), yauuid::Version(1));
            assert_eq!(u.variant(), yauuid::Variant::RFC4122);
        })
    });
}

fn benchmark_uuid_new_v1(c: &mut Criterion) {
    c.bench_function("uuid: new_v1", |b| {
        b.iter(|| {
            let ctx = uuid::v1::Context::new(42);
            let node = yauuid::Node::new("lo");

            let u = uuid::Uuid::new_v1(&ctx, 1497624119, 1234, &node.id()).unwrap();
            assert_eq!(u.get_version_num(), 1);
            assert_eq!(u.get_variant().unwrap(), uuid::Variant::RFC4122);
        })
    });
}

// new_v3 benchmark group
fn benchmark_yauuid_new_v3(c: &mut Criterion) {
    c.bench_function("yauuid: new_v3", |b| {
        b.iter(|| {
            let u = Uuid::new_v3(&Uuid::NAMESPACE_DNS, "python.org".as_bytes());
            assert_eq!(u.version(), yauuid::Version(3));
            assert_eq!(u.variant(), yauuid::Variant::RFC4122);
        })
    });
}

fn benchmark_uuid_new_v3(c: &mut Criterion) {
    c.bench_function("uuid: new_v3", |b| {
        b.iter(|| {
            let u = uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, "python.org".as_bytes());
            assert_eq!(u.get_version_num(), 3);
            assert_eq!(u.get_variant().unwrap(), uuid::Variant::RFC4122);
        })
    });
}

// new_v4 benchmark group
fn benchmark_yauuid_new_v4(c: &mut Criterion) {
    c.bench_function("yauuid: new_v4", |b| {
        b.iter(|| {
            let u = Uuid::new_v4();
            assert_eq!(u.version(), yauuid::Version(4));
            assert_eq!(u.variant(), yauuid::Variant::RFC4122);
        })
    });
}

fn benchmark_uuid_new_v4(c: &mut Criterion) {
    c.bench_function("uuid: new_v4", |b| {
        b.iter(|| {
            let u = uuid::Uuid::new_v4();
            assert_eq!(u.get_version_num(), 4);
            assert_eq!(u.get_variant().unwrap(), uuid::Variant::RFC4122);
        })
    });
}

// new_v5 benchmark group
fn benchmark_yauuid_new_v5(c: &mut Criterion) {
    c.bench_function("yauuid: new_v5", |b| {
        b.iter(|| {
            let u = Uuid::new_v5(&Uuid::NAMESPACE_DNS, "python.org".as_bytes());
            assert_eq!(u.version(), yauuid::Version(5));
            assert_eq!(u.variant(), yauuid::Variant::RFC4122);
        })
    });
}

fn benchmark_uuid_new_v5(c: &mut Criterion) {
    c.bench_function("uuid: new_v5", |b| {
        b.iter(|| {
            let u = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, "python.org".as_bytes());
            assert_eq!(u.get_version_num(), 5);
            assert_eq!(u.get_variant().unwrap(), uuid::Variant::RFC4122);
        })
    });
}

criterion_group!(uuid_from_str, benchmark_yauuid_from_str, benchmark_uuid_from_str);
criterion_group!(uuid_to_string, benchmark_yauuid_to_string, benchmark_uuid_to_string);
criterion_group!(uuid_new_v1, benchmark_yauuid_new_v1, benchmark_uuid_new_v1);
criterion_group!(uuid_new_v3, benchmark_yauuid_new_v3, benchmark_uuid_new_v3);
criterion_group!(uuid_new_v4, benchmark_yauuid_new_v4, benchmark_uuid_new_v4);
criterion_group!(uuid_new_v5, benchmark_yauuid_new_v5, benchmark_uuid_new_v5);
criterion_main!(uuid_from_str, uuid_to_string, uuid_new_v1, uuid_new_v3, uuid_new_v4, uuid_new_v5);
