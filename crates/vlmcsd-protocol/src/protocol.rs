#[cfg(test)]
use alloc::{format, vec};
use alloc::{string::String, vec::Vec};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::aes::{
    aes_cmac_v4, aes_decrypt_cbc, aes_encrypt_cbc_blocks, cipher_v5, cipher_v6, xor_block,
};
use crate::{Error, wire::Reader};

const REQUEST_SIZE: usize = 236;

/// Stable host identity and response policy for an emulated KMS host.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// Extended product ID, encoded as at most 63 UTF-16 code units.
    pub epid: String,
    /// Hardware ID returned in V6 responses.
    pub hardware_id: [u8; 8],
    /// Reported client count. This is an emulator setting, not a measured count.
    pub client_count: u32,
    /// Retry interval in minutes.
    pub activation_interval: u32,
    /// Renewal interval in minutes.
    pub renewal_interval: u32,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            epid: "03612-00206-471-111111-03-1033-17763.0000-0012024".into(),
            hardware_id: [0x36, 0x4f, 0x46, 0x3a, 0x88, 0x63, 0xd3, 0x5f],
            client_count: 50,
            activation_interval: 120,
            renewal_interval: 10080,
        }
    }
}

impl HostConfig {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.epid.is_empty() || self.epid.contains('\0') || self.epid.encode_utf16().count() > 63
        {
            return Err(Error::Config(
                "ePID must contain 1..=63 UTF-16 units and no NUL",
            ));
        }
        if self.activation_interval == 0 || self.renewal_interval == 0 {
            return Err(Error::Config(
                "activation and renewal intervals must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Validated, immutable response data shared by all connections.
pub struct PreparedHost {
    epid: Vec<u8>,
    hardware_id: [u8; 8],
    policy: [u8; 12],
}

impl PreparedHost {
    /// Validates and prepares immutable host response data.
    pub fn new(host: &HostConfig) -> Result<Self, Error> {
        host.validate()?;
        let epid = host
            .epid
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut policy = [0; 12];
        policy[..4].copy_from_slice(&host.client_count.to_le_bytes());
        policy[4..8].copy_from_slice(&host.activation_interval.to_le_bytes());
        policy[8..].copy_from_slice(&host.renewal_interval.to_le_bytes());
        Ok(Self {
            epid,
            hardware_id: host.hardware_id,
            policy,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    V4,
    V5,
    V6,
}

impl Version {
    fn parse(value: u32) -> Result<Self, Error> {
        match value {
            0x40000 => Ok(Self::V4),
            0x50000 => Ok(Self::V5),
            0x60000 => Ok(Self::V6),
            _ => Err(Error::Protocol("unsupported KMS version")),
        }
    }

    fn wire(self) -> [u8; 4] {
        let value: u32 = match self {
            Self::V4 => 0x40000,
            Self::V5 => 0x50000,
            Self::V6 => 0x60000,
        };
        value.to_le_bytes()
    }
}

struct Request {
    version: Version,
    cmid: [u8; 16],
    time: u64,
}

impl Request {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut input = Reader::new(bytes);
        let version = Version::parse(input.u32()?)?;
        // VM flag, license status, binding interval, application/activation/KMS IDs.
        input.take(60)?;
        let cmid = input.array()?;
        input.u32()?; // The client's activation threshold does not control our count.
        let time = input.u64()?;
        input.take(16)?; // Previous CMID.
        let name = input.take(128)?;
        let units = name.as_chunks::<2>().0;
        let end = units
            .iter()
            .position(|unit| *unit == [0; 2])
            .ok_or(Error::Protocol("invalid workstation name"))?;
        if char::decode_utf16(units[..end].iter().map(|unit| u16::from_le_bytes(*unit)))
            .any(|unit| unit.is_err())
        {
            return Err(Error::Protocol("invalid workstation name"));
        }
        input.finish()?;
        Ok(Self {
            version,
            cmid,
            time,
        })
    }

    fn write_response(&self, host: &PreparedHost, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.wire());
        out.extend_from_slice(&(host.epid.len() as u32).to_le_bytes());
        out.extend_from_slice(&host.epid);
        out.extend_from_slice(&self.cmid);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&host.policy);
    }
}

/// Appends a response; callers discard the buffer on error.
/// Supply fresh cryptographically random blocks for `random` and `response_iv`.
pub fn respond_into(
    bytes: &[u8],
    host: &PreparedHost,
    out: &mut Vec<u8>,
    random: [u8; 16],
    response_iv: [u8; 16],
) -> Result<(), Error> {
    let start = out.len();
    let version = Version::parse(Reader::new(bytes).u32()?)?;
    if version == Version::V4 {
        if bytes.len() != REQUEST_SIZE + 16 {
            return Err(Error::Protocol("invalid V4 request size"));
        }
        let (base, signature) = bytes.split_at(REQUEST_SIZE);
        if !bool::from(aes_cmac_v4(base).ct_eq(signature)) {
            return Err(Error::Protocol("invalid V4 request MAC"));
        }
        Request::parse(base)?.write_response(host, out);
        out.extend_from_slice(&aes_cmac_v4(&out[start..]));
        return Ok(());
    }

    if bytes.len() != 260 {
        return Err(Error::Protocol("invalid encrypted request size"));
    }
    let v6 = version == Version::V6;
    let mut plaintext = [0; 256];
    plaintext.copy_from_slice(&bytes[4..]);
    // KMS decrypts the transmitted IV as a block using an all-zero CBC IV.
    if v6 {
        aes_decrypt_cbc(&cipher_v6(), None, &mut plaintext);
    } else {
        aes_decrypt_cbc(&cipher_v5(), None, &mut plaintext);
    }
    if plaintext[252..] != [4; 4] {
        return Err(Error::Protocol("invalid request padding"));
    }
    let mut input = Reader::new(&plaintext);
    let request_iv: [u8; 16] = input.array()?;
    let request = Request::parse(input.take(REQUEST_SIZE)?)?;
    if request.version != version {
        return Err(Error::Protocol("inner and outer versions differ"));
    }

    let mut xored_random = random;
    xor_block(&mut xored_random, &request_iv);
    out.extend_from_slice(&version.wire());
    let encrypted_start = out.len();
    out.extend_from_slice(&if v6 { response_iv } else { request_iv });
    request.write_response(host, out);
    out.extend_from_slice(&xored_random);
    out.extend_from_slice(&Sha256::digest(random));
    if v6 {
        out.extend_from_slice(&host.hardware_id);
        out.extend_from_slice(&request_iv);
        let slot = (request.time / 0x00000022816889bd)
            .wrapping_mul(0x000000208cbab5ed)
            .wrapping_add(0x3156cd5ac628477a);
        let hash = Sha256::digest(slot.to_le_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&hash[16..])
            .map_err(|_| Error::Protocol("invalid HMAC key size"))?;
        mac.update(&out[encrypted_start..]);
        out.extend_from_slice(&mac.finalize().into_bytes()[16..]);
    }
    let padding = 16 - (out.len() - encrypted_start) % 16;
    out.resize(out.len() + padding, padding as u8);
    let blocks = out[encrypted_start..].as_chunks_mut::<16>().0;
    if v6 {
        aes_encrypt_cbc_blocks(&cipher_v6(), None, blocks);
    } else {
        aes_encrypt_cbc_blocks(&cipher_v5(), None, blocks);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{AES_KEY_V5, AES_KEY_V6, AesCtx, aes_encrypt_cbc};

    fn respond(bytes: &[u8], host: &HostConfig) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        respond_into(
            bytes,
            &PreparedHost::new(host)?,
            &mut out,
            [0x42; 16],
            [0x24; 16],
        )?;
        Ok(out)
    }

    const V4: &[u8] = include_bytes!("../../../tests/fixtures/v4-request.bin");
    const V5: &[u8] = include_bytes!("../../../tests/fixtures/v5-request.bin");
    const V6: &[u8] = include_bytes!("../../../tests/fixtures/v6-request.bin");

    #[test]
    fn workstation_name_requires_terminated_valid_utf16() {
        for (units, valid) in [
            (vec![0], true),
            (vec![0xd83d, 0xde00, 0], true),
            (vec![0xd83d, 0], false),
            (vec![0xde00, 0], false),
            (vec![0x61; 64], false),
            ([vec![0x61; 63], vec![0]].concat(), true),
            (vec![0, 0xd83d], true), // Ignore bytes after the terminator.
        ] {
            let mut base = V4[..REQUEST_SIZE].to_vec();
            base[108..].fill(0);
            for (chunk, unit) in base[108..].chunks_exact_mut(2).zip(units) {
                chunk.copy_from_slice(&u16::to_le_bytes(unit));
            }
            assert_eq!(Request::parse(&base).is_ok(), valid);
        }
    }

    #[test]
    fn appended_responses_preserve_prefix_and_encode_maximum_epid() {
        let host = HostConfig {
            epid: format!("{}x", "😀".repeat(31)),
            client_count: 123,
            activation_interval: 456,
            renewal_interval: 789,
            ..HostConfig::default()
        };
        let prepared = PreparedHost::new(&host).unwrap();
        let expected_pid: Vec<_> = host
            .epid
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        for raw in [V4, V5, V6] {
            for prefix_len in [0, 1, 36, 48] {
                let mut out = vec![0xa5; prefix_len];
                respond_into(raw, &prepared, &mut out, [0x42; 16], [0x24; 16]).unwrap();
                assert_eq!(&out[..prefix_len], vec![0xa5; prefix_len]);
                let response = &out[prefix_len..];
                let base = if raw == V4 {
                    let end = response.len() - 16;
                    assert_eq!(&response[end..], aes_cmac_v4(&response[..end]));
                    response[..end].to_vec()
                } else {
                    let mut plain = response[4..].to_vec();
                    let cipher =
                        AesCtx::new(if raw == V6 { AES_KEY_V6 } else { AES_KEY_V5 }, raw == V6);
                    aes_decrypt_cbc(&cipher, None, &mut plain);
                    let padding = usize::from(*plain.last().unwrap());
                    assert!((1..=16).contains(&padding));
                    assert!(
                        plain[plain.len() - padding..]
                            .iter()
                            .all(|byte| usize::from(*byte) == padding)
                    );
                    plain[16..16 + 44 + expected_pid.len()].to_vec()
                };
                assert_eq!(&base[..4], &raw[..4]);
                assert_eq!(&base[4..8], &128u32.to_le_bytes());
                assert_eq!(&base[8..136], &expected_pid);
                assert_eq!(
                    &base[136..160],
                    &V4[64..80]
                        .iter()
                        .chain(&V4[84..92])
                        .copied()
                        .collect::<Vec<_>>()
                );
                assert_eq!(&base[160..164], &123u32.to_le_bytes());
                assert_eq!(&base[164..168], &456u32.to_le_bytes());
                assert_eq!(&base[168..172], &789u32.to_le_bytes());
            }
        }
    }

    #[test]
    fn v4_response_matches_python_byte_for_byte() {
        assert_eq!(
            respond(V4, &HostConfig::default()).unwrap(),
            include_bytes!("../../../tests/fixtures/v4-response.bin")
        );
    }

    #[test]
    fn encrypted_responses_preserve_python_request_identity_and_policy() {
        for (request, expected, v6) in [
            (
                V5,
                include_bytes!("../../../tests/fixtures/v5-response-base.bin").as_slice(),
                false,
            ),
            (
                V6,
                include_bytes!("../../../tests/fixtures/v6-response-base.bin").as_slice(),
                true,
            ),
        ] {
            let response = respond(request, &HostConfig::default()).unwrap();
            let cipher = AesCtx::new(if v6 { AES_KEY_V6 } else { AES_KEY_V5 }, v6);
            let mut plain = response[4..].to_vec();
            aes_decrypt_cbc(&cipher, None, &mut plain);
            assert_eq!(&plain[16..16 + expected.len()], expected);
            let padding = usize::from(*plain.last().unwrap());
            assert!((1..=16).contains(&padding));
            assert!(
                plain[plain.len() - padding..]
                    .iter()
                    .all(|byte| usize::from(*byte) == padding)
            );
            if !v6 {
                assert_eq!(&response[4..20], &request[4..20]);
            }
        }
    }

    #[test]
    fn every_truncated_request_and_trailing_data_is_rejected() {
        for request in [V4, V5, V6] {
            for size in 0..request.len() {
                assert!(
                    respond(&request[..size], &HostConfig::default()).is_err(),
                    "size {size}"
                );
            }
            let mut extended = request.to_vec();
            extended.push(0);
            assert!(respond(&extended, &HostConfig::default()).is_err());
        }
    }

    #[test]
    fn v4_rejects_corrupted_mac() {
        let mut request = V4.to_vec();
        request[251] ^= 1;
        assert!(respond(&request, &HostConfig::default()).is_err());
    }

    #[test]
    fn encrypted_request_rejects_padding_and_version_mismatch() {
        for request in [V5, V6] {
            let mut corrupted = request.to_vec();
            // Flip a byte in the previous CBC block to corrupt exactly one padding byte.
            corrupted[243] ^= 1;
            assert!(respond(&corrupted, &HostConfig::default()).is_err());
            let mut mismatch = request.to_vec();
            // First ciphertext block is the transmitted IV; changing it changes inner version.
            mismatch[4] ^= 1;
            assert!(respond(&mismatch, &HostConfig::default()).is_err());
        }
    }

    #[test]
    fn unsupported_minor_version_is_rejected() {
        let mut request = V4.to_vec();
        request[0] = 1;
        assert!(respond(&request, &HostConfig::default()).is_err());
    }

    #[test]
    fn maximum_timestamp_and_client_threshold_do_not_overflow() {
        let mut base = V4[..236].to_vec();
        base[80..84].copy_from_slice(&u32::MAX.to_le_bytes());
        base[84..92].copy_from_slice(&u64::MAX.to_le_bytes());
        base[2] = 6;
        let cipher = AesCtx::new(AES_KEY_V6, true);
        let mut encrypted = [0; 16].to_vec();
        encrypted.extend_from_slice(&base);
        aes_encrypt_cbc(&cipher, None, &mut encrypted);
        let mut request = 0x60000u32.to_le_bytes().to_vec();
        request.extend_from_slice(&encrypted);
        assert!(respond(&request, &HostConfig::default()).is_ok());
    }

    #[test]
    fn epid_validation_counts_utf16_units() {
        let mut host = HostConfig {
            epid: "😀".repeat(31),
            ..HostConfig::default()
        };
        assert!(host.validate().is_ok());
        host.epid.push('😀');
        assert!(host.validate().is_err());
        host.epid = "abc\0def".into();
        assert!(host.validate().is_err());
    }
}
