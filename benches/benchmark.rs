use aes_wasm::*;

use aegis::aegis128l::Aegis128L;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::Payload;
use aes_gcm::aes;
use aes_gcm::{aead::Aead as _, aead::KeyInit as _, Aes128Gcm, Aes256Gcm};
use cmac::Cmac;

use benchmark_simple::*;

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

fn test_aes256gcm_rust(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes256Gcm::new(key);
    black_box(state.encrypt(nonce, Payload { msg: m, aad: &[] }).unwrap());
}

fn test_aes128gcm_rust(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&[0u8; 16]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    black_box(state.encrypt(nonce, Payload { msg: m, aad: &[] }).unwrap());
}

fn test_aegis128l_rust(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::<16>::new(&nonce, &key);
    black_box(state.encrypt(m, &[]));
}

fn test_aes128ctr_rust(m: &mut [u8]) {
    let key = [0u8; 16];
    let mut cipher = Aes128Ctr::new(&key.into(), &Default::default());
    let mut m2 = m.to_vec();
    cipher.apply_keystream(&mut m2);
    black_box(m2);
}

fn test_aes128gcm(m: &mut [u8]) {
    use aes128gcm::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
}

fn test_aes128ocb(m: &mut [u8]) {
    use aes128ocb::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
}

fn test_aegis128l(m: &mut [u8]) {
    use aegis128l::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
}

fn test_aes256gcm(m: &mut [u8]) {
    use aes256gcm::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
}

fn test_aes256ocb(m: &mut [u8]) {
    use aes256ocb::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
}

fn test_aegis256(m: &mut [u8]) {
    use aegis256::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
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

fn test_cmac_aes128_rust(m: &mut [u8]) {
    let key = [0u8; 16];
    let mut t = Cmac::<aes::Aes128>::new_from_slice(&key).unwrap();
    {
        use cmac::Mac as _;
        t.update(m);
        black_box(t.finalize().into_bytes());
    }
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

    let res = bench.run(options, || test_aes256gcm_rust(&mut m));
    println!(
        "aes256-gcm   (aes crate)  : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!(
        "aes256-gcm   (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128gcm_rust(&mut m));
    println!(
        "aes128-gcm   (aes crate)  : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128gcm(&mut m));
    println!(
        "aes128-gcm   (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes256ocb(&mut m));
    println!(
        "aes256-ocb   (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128ocb(&mut m));
    println!(
        "aes128-ocb   (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aegis256(&mut m));
    println!(
        "aegis-256    (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128l_rust(&mut m));
    println!(
        "aegis-128l   (aegis)      : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128l(&mut m));
    println!(
        "aegis-128l   (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128ctr_rust(&mut m));
    println!(
        "aes128-ctr   (ctr)        : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes128ctr(&mut m));
    println!(
        "aes128-ctr   (this crate) : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_cmac_aes128_rust(&mut m));
    println!(
        "cmac-aes128  (cmac)       : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_cmac_aes128(&mut m));
    println!(
        "cmac-aes128  (this crate) : {}",
        res.throughput(m.len() as _)
    );
}
