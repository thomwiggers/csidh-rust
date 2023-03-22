use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use csidh_rust::*;
use paste::paste;

pub fn criterion_benchmark(c: &mut Criterion) {
    macro_rules! bench {
        ($c: ident, $size: literal) => {
            let size: u32 = $size;
            $c.bench_function(&format!("ctidh {size} keypair"), |b| {
                b.iter(|| {
                    paste! {
                        [< ctidh $size >]::keypair()
                    }
                })
            });
            let keys = paste! { [< ctidh $size >]::keypair() };
            $c.bench_with_input(BenchmarkId::new("csidh action", "512"), &keys, |b, &keys| {
                b.iter(|| {
                    paste! {
                        [<ctidh $size>]::agreement(&keys.0, &keys.1)
                    }
                })
            })
        };
    }
    bench!(c, 511);
    bench!(c, 512);
    bench!(c, 1024);
    bench!(c, 2048);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
