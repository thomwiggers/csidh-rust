extern crate cc;

use std::path::Path;

fn main() {
    let ctidh_path = Path::new("high-ctidh-20210523");
    let ctidh_generic_files: Vec<_> = ["randombytes.c", "random.c", "int32_sort.c", "steps.c", "steps_untuned.c", "crypto_classify.c", "crypto_declassify.c"]
        .into_iter()
        .map(|f| ctidh_path.clone().join(f))
        .collect();
    cc::Build::new()
        .flag("-std=gnu99")
        .flag("-O3")
        .flag("-funroll-loops")
        .flag("-march=native")
        .flag("-Wno-unused-parameter")
        .flag("-DNAMESPACEGENERIC(x)=ctidh_rust_highctidh_generic_##x")
        .files(ctidh_generic_files)
        .compile("libctidh_generic.a");

    println!("cargo:rustc-link-lib=ctidh_generic");


    for size in ["512", "1024"] {
        let ctidh_n_files: Vec<_> = [
            "csidh.c",
            "uintbig{size}.S",
            "fp{size}.S",
            "fp_inv{size}.c",
            "fp_sqrt{size}.c",
            "primes{size}.c",
            "poly.c",
            "elligator.c",
            "validate.c",
            "mont.c",
            "skgen.c",
        ]
        .into_iter()
        .map(|f| ctidh_path.clone().join(f.replace("{size}", size)))
        .collect();
        cc::Build::new()
            .flag("-std=gnu99")
            .flag("-O3")
            .flag("-funroll-loops")
            .flag("-march=native")
            .flag("-Wno-unused-parameter")
            .flag(&format!("-DBITS={size}"))
            .flag("-DNAMESPACEGENERIC(x)=ctidh_rust_highctidh_generic_##x")
            .flag(&format!("-DNAMESPACEBITS(x)=ctidh_rust_highctidh_{size}_##x"))
            .files(ctidh_n_files)
            .compile(&format!("libctidh_{size}.a"));
    }
}
