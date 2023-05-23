use aes_wasm::*;

use aegis::aegis128l::Aegis128L;
use aes_gcm::{aead::AeadInPlace as _, aead::KeyInit as _, Aes128Gcm, Aes256Gcm};

use benchmark_simple::*;

fn test_aes256gcm_rust(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes256Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_aes128gcm_rust(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&[0u8; 16]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_aegis128l_rust(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aes128gcm(m: &mut [u8]) {
    use aes128gcm::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, &[], &key, nonce));
}

fn test_aes128ocb(m: &mut [u8]) {
    use aes128ocb::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, &[], &key, nonce));
}

fn test_aegis128l(m: &mut [u8]) {
    use aegis128l::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, &[], &key, nonce));
}

fn test_aes256gcm(m: &mut [u8]) {
    use aes256gcm::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, &[], &key, nonce));
}

fn test_aes256ocb(m: &mut [u8]) {
    use aes256ocb::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, &[], &key, nonce));
}

fn test_aegis256(m: &mut [u8]) {
    use aegis256::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, &[], &key, nonce));
}

fn test_aes128ctr(m: &mut [u8]) {
    use aes128ctr::*;
    let key = Key::default();
    let iv = IV::default();
    black_box(encrypt(m, &key, iv));
}

fn test_cmac_aes128(m: &mut [u8]) {
    use cmac_aes128::*;
    let key = Key::default();
    black_box(mac(m, &key));
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 10_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_aegis128l_rust(&mut m));
    println!(
        "aegis-128l   (aegis crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128gcm_rust(&mut m));
    println!(
        "aes-128-gcm  (aes crate)   : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes256gcm_rust(&mut m));
    println!(
        "aes-256-gcm  (aes crate)   : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128gcm(&mut m));
    println!(
        "aes128-gcm   (aes-wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128ocb(&mut m));
    println!(
        "aes128-ocb   (aes-wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128l(&mut m));
    println!(
        "aegis-128l   (aes_wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!(
        "aes256-gcm   (aes-wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes256ocb(&mut m));
    println!(
        "aes256-ocb   (aes-wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aegis256(&mut m));
    println!(
        "aegis-256    (aes_wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128ctr(&mut m));
    println!(
        "aes-128-ctr  (aes_wasm)    : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_cmac_aes128(&mut m));
    println!(
        "cmac-aes-128 (aes_wasm)    : {}",
        res.throughput(m.len() as _)
    );
}
