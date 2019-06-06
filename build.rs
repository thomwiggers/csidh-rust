extern crate cc;

use std::path::Path;

fn main() {
    let csidh_path = Path::new("constant-csidh-c-implementation");
    let csidh_files: Vec<_> = ["rng.c", "mont.c", "fp.S", "u512.S", "csidh.c", "libcsidh.c"].into_iter().map(|f|
        csidh_path.clone().join(f)).collect();
    cc::Build::new()
        .flag("-std=c99")
        .flag("-O3")
        .flag("-funroll-loops")
        .files(csidh_files)
        .compile("libcsidh.a");
}
