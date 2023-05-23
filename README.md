[![Docs.rs](https://docs.rs/aes-wasm/badge.svg)](https://docs.rs/aes-wasm/)
[![crates.io](https://img.shields.io/crates/v/aes-wasm.svg)](https://crates.io/crates/aes-wasm)

# Fast(er) AES-based constructions for Rust and WebAssembly

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

| algorithm   | crate           | throughput |
| ----------- | --------------- | ---------- |
| aes256-gcm  | (`aes` crate)   | 49.63 M/s  |
| aes256-gcm  | __this crate__  | 112.81 M/s |
| aes128-gcm  | (`aes` crate)   | 59.87 M/s  |
| aes128-gcm  | __this crate__  | 112.24 M/s |
| aes256-ocb  | __this crate__  | 168.43 M/s |
| aes128-ocb  | __this crate__  | 215.23 M/s |
| aegis-256   | __this crate__  | 478.57 M/s |
| aegis-128l  | (`aegis` crate) | 62.84 M/s  |
| aegis-128l  | __this crate__  | 695.85 M/s |
| aes128-ctr  | (`ctr` crate)   | 104.63 M/s |
| aes128-ctr  | __this crate__  | 214.81 M/s |
| cmac-aes128 | (`cmac` crate)  | 53.99 M/s  |
| cmac-aes128 | __this crate__  | 233.34 M/s |

Performance results using Wasmtime 9.0.1 on Ryzen 7

| algorithm   | crate           | throughput |
| ----------- | --------------- | ---------- |
| aes256-gcm  | (`aes` crate)   | 63.79 M/s  |
| aes256-gcm  | __this crate__  | 149.01 M/s |
| aes128-gcm  | (`aes` crate)   | 75.09 M/s  |
| aes128-gcm  | __this crate__  | 149.31 M/s |
| aes256-ocb  | __this crate__  | 200.93 M/s |
| aes128-ocb  | __this crate__  | 260.56 M/s |
| aegis-256   | __this crate__  | 497.97 M/s |
| aegis-128l  | (`aegis` crate) | 73.15 M/s  |
| aegis-128l  | __this crate__  | 696.61 M/s |
| aes128-ctr  | (`ctr` crate)   | 151.26 M/s |
| aes128-ctr  | __this crate__  | 275.51 M/s |
| cmac-aes128 | (`cmac` crate)  | 78.63 M/s  |
| cmac-aes128 | __this crate__  | 260.23 M/s |
