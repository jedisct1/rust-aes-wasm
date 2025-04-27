[![Docs.rs](https://docs.rs/aes-wasm/badge.svg)](https://docs.rs/aes-wasm/)
[![crates.io](https://img.shields.io/crates/v/aes-wasm.svg)](https://crates.io/crates/aes-wasm)

# aes-wasm

**Fast, dependency-free AES and AEGIS ciphers for Rust and WASI (WebAssembly System Interface)**

`aes-wasm` provides high-performance AEAD, stream cipher, and MAC primitives for use in WebAssembly/WASI environments. It is designed for speed, simplicity, and zero dependencies, making it ideal for cryptographic operations in WASI-based runtimes and server-side WASM applications.

> **Note:** This crate is intended specifically for WASI (not web browsers or native environments).

## Features

- **AEAD ciphers:**
  - AEGIS-128L, AEGIS-128X2, AEGIS-128X4
  - AEGIS-256, AEGIS-256X2, AEGIS-256X4
  - AES-128-GCM, AES-256-GCM
  - AES-128-OCB, AES-256-OCB
- **Stream ciphers:**
  - AES-128-CTR, AES-256-CTR
- **Block ciphers:**
  - AES-128-CBC, AES-256-CBC (with PKCS#7 padding)
- **MAC:**
  - CMAC-AES-128
- **Zero dependencies**
- **Simple, consistent API**
- **Optimized for WASI**

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
aes-wasm = "*"
```

> **Note:** Make sure your target is set to a WASI platform, such as `wasm32-wasi`.

## Usage

### AEAD Example: AES-128-GCM

```rust
use aes_wasm::aes128gcm::{encrypt, decrypt, Key, Nonce};
let key = Key::default();
let nonce = Nonce::default();
let msg = b"hello world";
let ad = b"extra data";
let ciphertext = encrypt(msg, ad, &key, nonce);
let plaintext = decrypt(ciphertext, ad, &key, nonce).unwrap();
assert_eq!(plaintext, msg);
```

### Stream Cipher Example: AES-128-CTR

```rust
use aes_wasm::aes128ctr::{encrypt, decrypt, Key, IV};
let key = Key::default();
let iv = IV::default();
let msg = b"streaming!";
let ciphertext = encrypt(msg, &key, iv);
let plaintext = decrypt(ciphertext, &key, iv);
assert_eq!(plaintext, msg);
```

### MAC Example: CMAC-AES-128

```rust
use aes_wasm::cmac_aes128::{mac, Key};
let key = Key::default();
let msg = b"authenticate me";
let tag = mac(msg, &key);
```

## Supported Algorithms

- **AEGIS:** 128L, 128X2, 128X4, 256, 256X2, 256X4
- **AES:** 128/256 GCM, 128/256 OCB, 128/256 CBC (PKCS#7), 128/256 CTR
- **CMAC:** AES-128

## Safety and Security

- This crate is designed for use in WASI only.
- Always use unique nonces for each encryption operation with AEAD ciphers.
- Review the documentation for each algorithm for security notes and usage patterns.

## Benchmarks

Benchmarks can be run with:

```
cargo wasix bench
```

### Wasmtime 9.0.1 on Apple M1

| algorithm   |      crate      | throughput |
| :---------- | :-------------: | ---------: |
| aes256-gcm  |  (`aes` crate)  |  49.63 M/s |
| aes256-gcm  |  _this crate_   |  98.86 M/s |
| aes128-gcm  |  (`aes` crate)  |  59.87 M/s |
| aes128-gcm  |  _this crate_   | 115.47 M/s |
| aes256-ocb  |  _this crate_   | 168.43 M/s |
| aes128-ocb  |  _this crate_   | 215.23 M/s |
| aes-128-cbc |  (`cbc` crate)  |  48.48 M/s |
| aes-128-cbc |  _this crate_   | 225.63 M/s |
| aes-256-cbc |  (`cbc` crate)  |  35.49 M/s |
| aes-256-cbc |  _this crate_   | 171.89 M/s |
| aegis-256   |  _this crate_   | 478.57 M/s |
| aegis-128l  | (`aegis` crate) | 533.85 M/s |
| aegis-128l  |  _this crate_   | 695.85 M/s |
| aes128-ctr  |  (`ctr` crate)  | 104.63 M/s |
| aes128-ctr  |  _this crate_   | 217.10 M/s |
| cmac-aes128 | (`cmac` crate)  |  53.99 M/s |
| cmac-aes128 |  _this crate_   | 233.34 M/s |

### Wasmtime 9.0.1 on Ryzen 7

| algorithm   |      crate      | throughput |
| :---------- | :-------------: | ---------: |
| aes256-gcm  |  (`aes` crate)  |  63.79 M/s |
| aes256-gcm  |  _this crate_   | 129.44 M/s |
| aes128-gcm  |  (`aes` crate)  |  75.09 M/s |
| aes128-gcm  |  _this crate_   | 149.31 M/s |
| aes256-ocb  |  _this crate_   | 205.39 M/s |
| aes128-ocb  |  _this crate_   | 260.56 M/s |
| aegis-256   |  _this crate_   | 497.97 M/s |
| aegis-128l  | (`aegis` crate) | 537.49 M/s |
| aegis-128l  |  _this crate_   | 696.61 M/s |
| aes128-ctr  |  (`ctr` crate)  | 151.26 M/s |
| aes128-ctr  |  _this crate_   | 275.51 M/s |
| cmac-aes128 | (`cmac` crate)  |  78.63 M/s |
| cmac-aes128 |  _this crate_   | 260.23 M/s |

## Documentation

- [API Documentation (docs.rs)](https://docs.rs/aes-wasm/)
- [Crate on crates.io](https://crates.io/crates/aes-wasm)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
