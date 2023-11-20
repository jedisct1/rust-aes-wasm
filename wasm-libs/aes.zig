const std = @import("std");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Aes128Ocb = std.crypto.aead.aes_ocb.Aes128Ocb;
const Aes256Ocb = std.crypto.aead.aes_ocb.Aes256Ocb;
const Aegis128L = std.crypto.aead.aegis.Aegis128L_256;
const Aegis256 = std.crypto.aead.aegis.Aegis256_256;
const CmacAes128 = std.crypto.auth.cmac.CmacAes128;
const modes = std.crypto.core.modes;

pub const std_options = struct {
    pub const side_channels_mitigations = .none;
};

// AES128-GCM

export fn aes128gcm_encrypt(
    c: [*c]u8,
    c_len: usize,
    tag: [*c][Aes128Gcm.tag_length]u8,
    m: [*c]const u8,
    m_len: usize,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes128Gcm.nonce_length]u8,
    k: [*c]const [Aes128Gcm.key_length]u8,
) callconv(.C) i32 {
    Aes128Gcm.encrypt(c[0..c_len], tag, m[0..m_len], ad[0..ad_len], nonce.*, k.*);
    return 0;
}

export fn aes128gcm_decrypt(
    m: [*c]u8,
    m_len: usize,
    c: [*c]const u8,
    c_len: usize,
    tag: [*c]const [Aes128Gcm.tag_length]u8,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes128Gcm.nonce_length]u8,
    k: [*c]const [Aes128Gcm.key_length]u8,
) callconv(.C) i32 {
    Aes128Gcm.decrypt(m[0..m_len], c[0..c_len], tag.*, ad[0..ad_len], nonce.*, k.*) catch return -1;
    return 0;
}

// AES256-GCM

export fn aes256gcm_encrypt(
    c: [*c]u8,
    c_len: usize,
    tag: [*c][Aes256Gcm.tag_length]u8,
    m: [*c]const u8,
    m_len: usize,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes256Gcm.nonce_length]u8,
    k: [*c]const [Aes256Gcm.key_length]u8,
) callconv(.C) i32 {
    Aes256Gcm.encrypt(c[0..c_len], tag, m[0..m_len], ad[0..ad_len], nonce.*, k.*);
    return 0;
}

export fn aes256gcm_decrypt(
    m: [*c]u8,
    m_len: usize,
    c: [*c]const u8,
    c_len: usize,
    tag: [*c]const [Aes256Gcm.tag_length]u8,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes256Gcm.nonce_length]u8,
    k: [*c]const [Aes256Gcm.key_length]u8,
) callconv(.C) i32 {
    Aes256Gcm.decrypt(m[0..m_len], c[0..c_len], tag.*, ad[0..ad_len], nonce.*, k.*) catch return -1;
    return 0;
}

// AES128-OCB

export fn aes128ocb_encrypt(
    c: [*c]u8,
    c_len: usize,
    tag: [*c][Aes128Ocb.tag_length]u8,
    m: [*c]const u8,
    m_len: usize,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes128Ocb.nonce_length]u8,
    k: [*c]const [Aes128Ocb.key_length]u8,
) callconv(.C) i32 {
    Aes128Ocb.encrypt(c[0..c_len], tag, m[0..m_len], ad[0..ad_len], nonce.*, k.*);
    return 0;
}

export fn aes128ocb_decrypt(
    m: [*c]u8,
    m_len: usize,
    c: [*c]const u8,
    c_len: usize,
    tag: [*c]const [Aes128Ocb.tag_length]u8,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes128Ocb.nonce_length]u8,
    k: [*c]const [Aes128Ocb.key_length]u8,
) callconv(.C) i32 {
    Aes128Ocb.decrypt(m[0..m_len], c[0..c_len], tag.*, ad[0..ad_len], nonce.*, k.*) catch return -1;
    return 0;
}

// AES256-OCB

export fn aes256ocb_encrypt(
    c: [*c]u8,
    c_len: usize,
    tag: [*c][Aes256Ocb.tag_length]u8,
    m: [*c]const u8,
    m_len: usize,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes256Ocb.nonce_length]u8,
    k: [*c]const [Aes256Ocb.key_length]u8,
) callconv(.C) i32 {
    Aes256Ocb.encrypt(c[0..c_len], tag, m[0..m_len], ad[0..ad_len], nonce.*, k.*);
    return 0;
}

export fn aes256ocb_decrypt(
    m: [*c]u8,
    m_len: usize,
    c: [*c]const u8,
    c_len: usize,
    tag: [*c]const [Aes256Ocb.tag_length]u8,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aes256Ocb.nonce_length]u8,
    k: [*c]const [Aes256Ocb.key_length]u8,
) callconv(.C) i32 {
    Aes256Ocb.decrypt(m[0..m_len], c[0..c_len], tag.*, ad[0..ad_len], nonce.*, k.*) catch return -1;
    return 0;
}

// AEGIS-128L

export fn aegis128l_encrypt(
    c: [*c]u8,
    c_len: usize,
    tag: [*c][Aegis128L.tag_length]u8,
    m: [*c]const u8,
    m_len: usize,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aegis128L.nonce_length]u8,
    k: [*c]const [Aegis128L.key_length]u8,
) callconv(.C) i32 {
    Aegis128L.encrypt(c[0..c_len], tag, m[0..m_len], ad[0..ad_len], nonce.*, k.*);
    return 0;
}

export fn aegis128l_decrypt(
    m: [*c]u8,
    m_len: usize,
    c: [*c]const u8,
    c_len: usize,
    tag: [*c]const [Aegis128L.tag_length]u8,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aegis128L.nonce_length]u8,
    k: [*c]const [Aegis128L.key_length]u8,
) callconv(.C) i32 {
    Aegis128L.decrypt(m[0..m_len], c[0..c_len], tag.*, ad[0..ad_len], nonce.*, k.*) catch return -1;
    return 0;
}

// AEGIS-256

export fn aegis256_encrypt(
    c: [*c]u8,
    c_len: usize,
    tag: [*c][Aegis256.tag_length]u8,
    m: [*c]const u8,
    m_len: usize,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aegis256.nonce_length]u8,
    k: [*c]const [Aegis256.key_length]u8,
) callconv(.C) i32 {
    Aegis256.encrypt(c[0..c_len], tag, m[0..m_len], ad[0..ad_len], nonce.*, k.*);
    return 0;
}

export fn aegis256_decrypt(
    m: [*c]u8,
    m_len: usize,
    c: [*c]const u8,
    c_len: usize,
    tag: [*c]const [Aegis256.tag_length]u8,
    ad: [*c]const u8,
    ad_len: usize,
    nonce: [*c]const [Aegis256.nonce_length]u8,
    k: [*c]const [Aegis256.key_length]u8,
) callconv(.C) i32 {
    Aegis256.decrypt(m[0..m_len], c[0..c_len], tag.*, ad[0..ad_len], nonce.*, k.*) catch return -1;
    return 0;
}

// AES-128-CTR

export fn aes128ctr(
    out: [*c]u8,
    out_len: usize,
    in: [*c]const u8,
    in_len: usize,
    iv: [*c]const [16]u8,
    k: [*c]const [16]u8,
) callconv(.C) i32 {
    const aes = std.crypto.core.aes.Aes128.initEnc(k.*);
    modes.ctr(@TypeOf(aes), aes, out[0..out_len], in[0..in_len], iv.*, std.builtin.Endian.big);
    return 0;
}

// AES-256-CTR

export fn aes256ctr(
    out: [*c]u8,
    out_len: usize,
    in: [*c]const u8,
    in_len: usize,
    iv: [*c]const [16]u8,
    k: [*c]const [32]u8,
) callconv(.C) i32 {
    const aes = std.crypto.core.aes.Aes256.initEnc(k.*);
    modes.ctr(@TypeOf(aes), aes, out[0..out_len], in[0..in_len], iv.*, std.builtin.Endian.big);
    return 0;
}

// CMAC-AES128

export fn cmac_aes128(
    out: [*c][CmacAes128.mac_length]u8,
    in: [*c]const u8,
    in_len: usize,
    k: [*c]const [CmacAes128.key_length]u8,
) callconv(.C) i32 {
    CmacAes128.create(out, in[0..in_len], k);
    return 0;
}
