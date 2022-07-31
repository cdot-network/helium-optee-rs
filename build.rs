use std::env;
use std::path::PathBuf;

fn main() {
    cc::Build::new()
        .include("c_src")
        .file("c_src/helium.c")
        .compile("helium");
    println!("cargo:rerun-if-changed=c_src/helium.c");
    println!("cargo:rerun-if-changed=c_src/helium.h");

    println!("cargo:rustc-link-lib=dylib=teec");

    let bindings = bindgen::Builder::default()
        .header("c_src/helium.h")
        .allowlist_function("helium_.*")
        .allowlist_function("gen_.*_keypair")
        .allowlist_function("del_.*_keypair")
        .allowlist_function("ecdsa_.*")
        .allowlist_function("ecdh")
        .allowlist_function("get_ecc_publickey")
        .generate()
        .expect("Unable to generate bindgen");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings.rs");
}
