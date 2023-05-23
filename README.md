# Fast AES-based constructions for Rust and WebAssembly

* AEGIS-128L
* AEGIS-256
* AES-128-CTR
* AES-256-CTR
* AES-128-OCB
* AES-256-OCB
* AES-128-GCM
* AES-256-GCM
* CMAC-AES-128

This is a set of AES-based constructions (AEAD, stream cipher, MAC) for WebAssembly applications written in Rust.

They are trivial to use and this crate has zero dependencies.

# Benchmarks

Benchmarks can be run with the `cargo wasi bench` command.

Performance results using Wasmtime 9.0.1 on Apple M1

| algorithm    | crate      | throughput |
| ------------ | ---------- | ---------- |
| aes-256-gcm  | aes-gcm    | 49.97 M/s  |
| aes-128-gcm  | aes-gcm    | 60.07 M/s  |
| aegis-128l   | aegis      | 63.03 M/s  |
| aes128-gcm   | THIS CRATE | 61.55 M/s  |
| aes256-gcm   | THIS CRATE | 61.57 M/s  |
| aes256-ocb   | THIS CRATE | 168.47 M/s |
| aes-128-ctr  | THIS CRATE | 214.49 M/s |
| aes128-ocb   | THIS CRATE | 215.41 M/s |
| cmac-aes-128 | THIS CRATE | 232.41 M/s |
| aegis-256    | THIS CRATE | 475.12 M/s |
| aegis-128l   | THIS CRATE | 697.36 M/s |



