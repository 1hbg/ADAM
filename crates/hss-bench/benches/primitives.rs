use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hss_bench::{ddlog, pow_signed, KeyMaterial};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rug::Integer;
use std::{fs::File, path::Path};

fn keys() -> KeyMaterial {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hss-key.bin");
    bincode::deserialize_from(
        File::open(path).expect("run `cargo run --release -p hss-bench -- keygen` first"),
    )
    .expect("read cached key")
}

fn primitives(c: &mut Criterion) {
    let keys = keys();
    let base = hss_bench::encrypt(&keys.public, &Integer::from(42));
    let mut exponent_bytes = [0_u8; 85];
    StdRng::seed_from_u64(0xE673).fill_bytes(&mut exponent_bytes);
    exponent_bytes[84] |= 1;
    let exponent = Integer::from_digits(&exponent_bytes, rug::integer::Order::Lsf);
    let g = pow_signed(&base, &exponent, &keys.public.n2);

    c.bench_function("modexp_N2_673_bit_dense_exponent", |b| {
        b.iter(|| {
            pow_signed(
                black_box(&base),
                black_box(&exponent),
                black_box(&keys.public.n2),
            )
        })
    });
    c.bench_function("DDLog", |b| {
        b.iter(|| ddlog(black_box(&keys.public.n), black_box(&g)))
    });
}

criterion_group!(benches, primitives);
criterion_main!(benches);
