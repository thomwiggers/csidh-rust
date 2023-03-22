use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use csidh_rust::*;
use paste::paste;

pub fn criterion_benchmark(crit: &mut Criterion) {
    let mut group = crit.benchmark_group("ctidh");
    group.measurement_time(std::time::Duration::new(90, 0));
    macro_rules! bench {
        ($c: ident, $size: literal) => {
            let size: u32 = $size;
            $c.bench_function(&format!("keypair/{size}"), |b| {
                b.iter(|| {
                    paste! {
                        [< ctidh $size >]::keypair()
                    }
                })
            });
            let keys = paste! { [< ctidh $size >]::keypair() };
            $c.bench_with_input(BenchmarkId::new("action", size), &keys, |b, &keys| {
                b.iter(|| {
                    paste! {
                        [<ctidh $size>]::agreement(&keys.0, &keys.1)
                    }
                })
            })
        };
    }
    bench!(group, 511);
    bench!(group, 512);
    bench!(group, 1024);
    bench!(group, 2048);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
