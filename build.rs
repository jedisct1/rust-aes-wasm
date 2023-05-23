use std::env;

pub fn main() {
    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-lib=static=aes");
    println!("cargo:rustc-link-search=native={}/wasm-libs", src_dir);
}
