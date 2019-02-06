#[macro_use]
extern crate criterion;
extern crate yauuid;
extern crate uuid;

use criterion::Criterion;
use yauuid::Uuid;
use std::str::FromStr;


const BENCHMARK_STRING: &str = "f47ac10b-58cc-0372-8567-0e02b2c3d479";

fn benchmark_from_str(c: &mut Criterion) {
    c.bench_function("from_str", |b| {
        b.iter(|| assert!(Uuid::from_str(BENCHMARK_STRING).is_ok()))
    });
}

fn benchmark_new_v4(c: &mut Criterion) {
    c.bench_function("new_v4", |b| {
        b.iter(|| Uuid::new_v4());
    });
}

criterion_group!(benches, benchmark_from_str, benchmark_uuidrs_from_str, benchmark_new_v4);
criterion_main!(benches);
