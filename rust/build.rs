// Build glue for the Rust rewrite of desens.
//
// Links against the vendored libmupdf.so.28.6 (copied from the pymupdf wheel;
// MuPDF is AGPL -- see rust/NOTICE) and compiles the C shim that wraps every
// MuPDF call which can longjmp in `fz_try`/`fz_catch`, so Rust frames never
// see a setjmp unwind.
use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let include = manifest.join("thirdparty/mupdf-1.28.6-source/include");
    let lib = manifest.join("lib");

    cc::Build::new()
        .file("src/shim.c")
        .include(&include)
        .flag_if_supported("-w")
        .compile("dsshim");

    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=dylib=mupdf");
    // the binary finds the vendored .so at runtime without ldconfig
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib.display());
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-changed=lib/libmupdf.so.28.6");
}
