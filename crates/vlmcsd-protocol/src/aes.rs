// Adapted from mingtsay/vlmcsd-rs (MIT), commit 010300220fa2aba848a45ce8073ae3e19869d8de.
// See the repository-root THIRD-PARTY-NOTICES. KMS-specific Rijndael, not a general cryptography API.

#[cfg(test)]
use alloc::vec::Vec;

use ::aes::{
    Aes128, Block,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
    hazmat::{cipher_round, inv_mix_columns},
};

pub(crate) fn cipher_v5() -> Aes128 {
    Aes128::new(&(*AES_KEY_V5).into())
}
pub(crate) fn cipher_v6() -> AesCtx {
    AesCtx::new(AES_KEY_V6, true)
}

pub const AES_KEY_V4: &[u8; 20] = &[
    0x05, 0x3D, 0x83, 0x07, 0xF9, 0xE5, 0xF0, 0x88, 0xEB, 0x5E, 0xA6, 0x68, 0x6C, 0xF0, 0x37, 0xC7,
    0xE4, 0xEF, 0xD2, 0xD6,
];

pub const AES_KEY_V5: &[u8; 16] = &[
    0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70,
];

pub const AES_KEY_V6: &[u8; 16] = &[
    0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21,
];

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

#[rustfmt::skip]
const SBOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

const RCON: [u32; 11] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1B000000, 0x36000000,
];

/// KMS V4 uses Rijndael with a 160-bit key and eleven rounds, not AES-128.
/// Keep its key expansion but delegate the round operations to RustCrypto.
struct V4Cipher {
    round_keys: [Block; 12],
}

impl V4Cipher {
    fn new(key: &[u8; 20]) -> Self {
        let expanded = AesCtx::new(key, false);
        let round_keys = core::array::from_fn(|round| {
            let mut bytes = [0; 16];
            for (chunk, word) in bytes
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(&expanded.key[round * 4..round * 4 + 4])
            {
                *chunk = word.to_le_bytes();
            }
            bytes.into()
        });
        Self { round_keys }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = Block::from(*block);
        for (byte, key) in state.iter_mut().zip(&self.round_keys[0]) {
            *byte ^= key;
        }
        for key in &self.round_keys[1..11] {
            cipher_round(&mut state, key);
        }
        // The final round omits MixColumns. A round with a zero key followed
        // by InvMixColumns leaves SubBytes + ShiftRows; then add the last key.
        cipher_round(&mut state, &Block::default());
        inv_mix_columns(&mut state);
        for (byte, key) in state.iter_mut().zip(&self.round_keys[11]) {
            *byte ^= key;
        }
        block.copy_from_slice(&state);
    }
}

/// Block operations shared by the V5 AES and V6 KMS-specific CBC paths.
pub(crate) trait CbcCipher {
    fn encrypt(&self, block: &mut [u8; 16]);
    fn decrypt(&self, block: &mut [u8; 16]);
}

impl CbcCipher for Aes128 {
    fn encrypt(&self, block: &mut [u8; 16]) {
        let mut state = Block::from(*block);
        self.encrypt_block(&mut state);
        block.copy_from_slice(&state);
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        let mut state = Block::from(*block);
        self.decrypt_block(&mut state);
        block.copy_from_slice(&state);
    }
}

pub struct AesCtx {
    key: [u32; 48],
    rounds: usize,
}

impl AesCtx {
    pub fn new(key_bytes: &[u8], is_v6: bool) -> Self {
        let key_dwords = key_bytes.len() / 4;
        let rounds = key_dwords + 6;
        let mut key = [0u32; 48];

        for i in 0..key_dwords {
            key[i] = u32::from_le_bytes([
                key_bytes[i * 4],
                key_bytes[i * 4 + 1],
                key_bytes[i * 4 + 2],
                key_bytes[i * 4 + 3],
            ]);
        }

        for i in key_dwords..((rounds + 1) * 4) {
            let mut temp = key[i - 1];
            if (i % key_dwords) == 0 {
                // BE32(temp) converts LE-stored dword to big-endian integer
                let be_val = temp.swap_bytes();
                // ROR32(x, 24) = rotate_right(24) = rotate_left(8) on the integer
                let rotated = be_val.rotate_left(8);
                // SubDword operates on bytes in memory (native) order
                let subbed = sub_dword(rotated);
                // XOR with RCon (big-endian constant), then BE32 to convert back to LE
                temp = (subbed ^ RCON[i / key_dwords]).swap_bytes();
            }
            key[i] = key[i - key_dwords] ^ temp;
        }

        if is_v6 {
            // Round keys are stored as little-endian words, independent of host endian.
            key[16] ^= 0x73;
            key[24] ^= 0x09;
            key[32] ^= 0xe4;
        }

        AesCtx { key, rounds }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut i = 0;
        loop {
            add_round_key(block, &self.key[i..i + 4]);
            sub_bytes(block);
            shift_rows(block);
            if i >= (self.rounds - 1) * 4 {
                break;
            }
            mix_columns(block);
            i += 4;
        }
        add_round_key(block, &self.key[self.rounds * 4..self.rounds * 4 + 4]);
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.key[self.rounds * 4..self.rounds * 4 + 4]);
        let mut i = (self.rounds - 1) * 4;
        loop {
            shift_rows_inv(block);
            sub_bytes_inv(block);
            add_round_key(block, &self.key[i..i + 4]);
            if i == 0 {
                break;
            }
            mix_columns_inv(block);
            i -= 4;
        }
    }
}

impl CbcCipher for AesCtx {
    fn encrypt(&self, block: &mut [u8; 16]) {
        self.encrypt_block(block);
    }

    fn decrypt(&self, block: &mut [u8; 16]) {
        self.decrypt_block(block);
    }
}

pub fn xor_block(dest: &mut [u8; 16], src: &[u8; 16]) {
    for (d, s) in dest.iter_mut().zip(src) {
        *d ^= s;
    }
}

#[cfg(test)]
pub fn aes_encrypt_cbc(ctx: &impl CbcCipher, iv: Option<&[u8; 16]>, data: &mut Vec<u8>) {
    let pad = 16 - data.len() % 16;
    data.resize(data.len() + pad, pad as u8);
    aes_encrypt_cbc_blocks(ctx, iv, data.as_chunks_mut::<16>().0);
}

pub fn aes_encrypt_cbc_blocks(
    ctx: &impl CbcCipher,
    iv: Option<&[u8; 16]>,
    blocks: &mut [[u8; 16]],
) {
    let mut previous = iv.copied().unwrap_or([0; 16]);
    for block in blocks {
        xor_block(block, &previous);
        ctx.encrypt(block);
        previous = *block;
    }
}

pub fn aes_decrypt_cbc(ctx: &impl CbcCipher, iv: Option<&[u8; 16]>, data: &mut [u8]) {
    // Callers validate ciphertext length before invoking this private primitive.
    let mut previous = iv.copied().unwrap_or([0; 16]);
    for block in data.as_chunks_mut::<16>().0 {
        let ciphertext = *block;
        ctx.decrypt(block);
        xor_block(block, &previous);
        previous = ciphertext;
    }
}

pub fn aes_cmac_v4(message: &[u8]) -> [u8; 16] {
    let ctx = &V4Cipher::new(AES_KEY_V4);
    let mut mac = [0; 16];
    let (blocks, tail) = message.as_chunks::<16>();
    for block in blocks {
        xor_block(&mut mac, block);
        ctx.encrypt_block(&mut mac);
    }
    let mut final_block = [0; 16];
    final_block[..tail.len()].copy_from_slice(tail);
    final_block[tail.len()] = 0x80;
    xor_block(&mut mac, &final_block);
    ctx.encrypt_block(&mut mac);
    mac
}

fn sub_dword(v: u32) -> u32 {
    let b = v.to_ne_bytes();
    u32::from_ne_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

fn add_round_key(block: &mut [u8; 16], rk: &[u32]) {
    for (chunk, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(rk) {
        let value = u32::from_le_bytes(*chunk) ^ word;
        *chunk = value.to_le_bytes();
    }
}

fn sub_bytes(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn sub_bytes_inv(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = SBOX_INV[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let input = *state;
    for i in 0..16 {
        state[i] = input[(i + ((i & 3) << 2)) & 0xf];
    }
}

fn shift_rows_inv(state: &mut [u8; 16]) {
    let input = *state;
    for i in 0..16 {
        state[i] = input[(i.wrapping_sub((i & 3) << 2)) & 0xf];
    }
}

fn mul2(word: u32) -> u32 {
    ((word & 0x7f7f7f7f) << 1) ^ (((word & 0x80808080) >> 7) * 0x1b)
}

fn mul3(word: u32) -> u32 {
    mul2(word) ^ word
}

fn mix_columns(state: &mut [u8; 16]) {
    for chunk in state.as_chunks_mut::<4>().0 {
        let word = u32::from_le_bytes(*chunk);
        let result =
            mul2(word) ^ mul3(word).rotate_right(8) ^ word.rotate_right(16) ^ word.rotate_right(24);
        *chunk = result.to_le_bytes();
    }
}

fn mul4(word: u32) -> u32 {
    mul2(mul2(word))
}

fn mul8(word: u32) -> u32 {
    mul2(mul2(mul2(word)))
}

fn mix_columns_inv(state: &mut [u8; 16]) {
    for chunk in state.as_chunks_mut::<4>().0 {
        let word = u32::from_le_bytes(*chunk);
        let mul_e = mul8(word) ^ mul4(word) ^ mul2(word);
        let mul_b = mul8(word) ^ mul3(word);
        let mul_d = mul8(word) ^ mul4(word) ^ word;
        let mul_9 = mul8(word) ^ word;
        let result =
            mul_e ^ mul_b.rotate_right(8) ^ mul_d.rotate_right(16) ^ mul_9.rotate_right(24);
        *chunk = result.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustcrypto_v4_matches_original_rounds_and_mac_boundaries() {
        let reference = AesCtx::new(AES_KEY_V4, false);
        for seed in 0..=255u8 {
            let mut actual = core::array::from_fn(|i| seed.wrapping_add(i as u8));
            let mut expected = actual;
            reference.encrypt_block(&mut expected);
            V4Cipher::new(AES_KEY_V4).encrypt_block(&mut actual);
            assert_eq!(actual, expected, "block seed {seed}");
        }
        // Include empty, exact-block, and partial-block inputs. KMS V4's MAC
        // always adds 0x80 padding, including a full block for aligned inputs.
        let bytes: Vec<u8> = (0..=255).collect();
        for len in 0..=bytes.len() {
            let mut padded = bytes[..len].to_vec();
            padded.push(0x80);
            padded.resize(padded.len().next_multiple_of(16), 0);
            let mut expected = [0; 16];
            for block in padded.as_chunks::<16>().0 {
                xor_block(&mut expected, block);
                reference.encrypt_block(&mut expected);
            }
            assert_eq!(aes_cmac_v4(&bytes[..len]), expected, "MAC length {len}");
        }
    }

    #[test]
    fn rustcrypto_v5_matches_original_cbc() {
        let reference = AesCtx::new(AES_KEY_V5, false);
        let bytes: Vec<u8> = (0..=255).collect();
        for iv in [None, Some([0xa5; 16])] {
            for len in 0..=bytes.len() {
                let mut expected = bytes[..len].to_vec();
                let mut actual = expected.clone();
                aes_encrypt_cbc(&reference, iv.as_ref(), &mut expected);
                aes_encrypt_cbc(&cipher_v5(), iv.as_ref(), &mut actual);
                assert_eq!(actual, expected, "CBC length {len}");
                aes_decrypt_cbc(&cipher_v5(), iv.as_ref(), &mut actual);
                aes_decrypt_cbc(&reference, iv.as_ref(), &mut expected);
                assert_eq!(actual, expected, "CBC decrypt length {len}");
                assert_eq!(&actual[..len], &bytes[..len]);
            }
        }
    }

    #[test]
    fn aes128_ecb_encrypt_nist() {
        // NIST FIPS 197 Appendix B
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        let ctx = AesCtx::new(&key, false);
        let mut block = plaintext;
        ctx.encrypt_block(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn aes128_ecb_decrypt_nist() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let expected: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];

        let ctx = AesCtx::new(&key, false);
        let mut block = ciphertext;
        ctx.decrypt_block(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn aes128_cbc_encrypt_nist() {
        // NIST SP 800-38A F.2.1
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected: [u8; 64] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];

        let ctx = AesCtx::new(&key, false);
        // Our CBC adds PKCS7 padding, so test with exact block-aligned data
        // by checking we get the right ciphertext for the first 64 bytes
        // We'll do a manual CBC to match NIST exactly (no padding)
        let mut output = plaintext;
        let mut prev = iv;
        for chunk_idx in 0..4 {
            let start = chunk_idx * 16;
            let block: &mut [u8; 16] = (&mut output[start..start + 16]).try_into().unwrap();
            xor_block(block, &prev);
            ctx.encrypt_block(block);
            prev = *block;
        }
        assert_eq!(output, expected);
    }

    #[test]
    fn aes128_cbc_decrypt_nist() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let ciphertext: [u8; 64] = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];
        let expected: [u8; 64] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];

        let ctx = AesCtx::new(&key, false);
        let mut data = ciphertext;
        aes_decrypt_cbc(&ctx, Some(&iv), &mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn aes_cbc_encrypt_decrypt_roundtrip() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"Hello, AES-CBC!!"; // exactly 16 bytes

        let ctx = AesCtx::new(&key, false);
        let mut data = plaintext.to_vec();
        aes_encrypt_cbc(&ctx, Some(&iv), &mut data);
        // After encryption, data is 32 bytes (16 original + 16 pad)
        assert_eq!(data.len(), 32);

        aes_decrypt_cbc(&ctx, Some(&iv), &mut data);
        // Strip PKCS7 padding
        let pad_len = data[data.len() - 1] as usize;
        data.truncate(data.len() - pad_len);
        assert_eq!(&data, plaintext);
    }

    #[test]
    fn aes_cmac_v4_basic() {
        // Verify CMAC produces consistent 16-byte output
        let message = [0u8; 32];
        let mac = aes_cmac_v4(&message);
        assert_eq!(mac.len(), 16);
        // Verify deterministic
        let mac2 = aes_cmac_v4(&message);
        assert_eq!(mac, mac2);
    }

    #[test]
    fn aes_v6_key_modification() {
        // Verify V6 key schedule produces different output than V5
        let ctx_v5 = AesCtx::new(AES_KEY_V6, false);
        let ctx_v6 = AesCtx::new(AES_KEY_V6, true);

        let mut block_v5 = [0u8; 16];
        let mut block_v6 = [0u8; 16];
        ctx_v5.encrypt_block(&mut block_v5);
        ctx_v6.encrypt_block(&mut block_v6);
        assert_ne!(block_v5, block_v6);
    }

    #[test]
    fn aes_160bit_key() {
        // Verify 160-bit (20 byte) key works (used by V4 CMAC)
        let ctx = AesCtx::new(AES_KEY_V4, false);
        let mut block = [0u8; 16];
        ctx.encrypt_block(&mut block);
        // Just verify it doesn't panic and produces non-zero output
        assert_ne!(block, [0u8; 16]);
    }
}
