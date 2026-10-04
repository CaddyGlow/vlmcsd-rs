use alloc::{string::String, vec::Vec};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    Error,
    aes::{aes_cmac_v4, aes_decrypt_cbc, aes_encrypt_cbc_blocks, cipher_v5, cipher_v6, xor_block},
    wire::Reader,
};

/// KMS protocol generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Version {
    /// Unencrypted requests authenticated with the V4 MAC.
    V4,
    /// AES encrypted requests and responses.
    V5,
    /// Modified AES with response HMAC and host hardware identity.
    #[default]
    V6,
}
impl Version {
    /// The protocol major version.
    pub fn major(self) -> u16 {
        match self {
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
        }
    }
    fn wire(self) -> [u8; 4] {
        (u32::from(self.major()) << 16).to_le_bytes()
    }
}

/// Request fields. GUIDs use Windows little-endian wire order.
#[derive(Clone, Debug)]
pub struct ActivationRequest {
    /// Protocol generation.
    pub version: Version,
    /// Whether the requesting machine is virtual.
    pub virtual_machine: bool,
    /// Software licensing status (2 means initial grace).
    pub license_status: u32,
    /// Binding expiration in minutes.
    pub binding_expiration: u32,
    /// Application GUID.
    pub application_id: [u8; 16],
    /// Product activation GUID.
    pub activation_id: [u8; 16],
    /// KMS counted product GUID.
    pub kms_id: [u8; 16],
    /// Client machine GUID.
    pub cmid: [u8; 16],
    /// Minimum client count requested by the product.
    pub required_count: u32,
    /// Windows FILETIME timestamp in 100 ns ticks since 1601.
    pub time: u64,
    /// Previous client machine GUID, or zero.
    pub previous_cmid: [u8; 16],
    /// Workstation name, at most 63 UTF-16 units without NUL.
    pub workstation: String,
}
impl ActivationRequest {
    /// Creates a request using caller-supplied CMID and FILETIME timestamp.
    /// Product GUIDs and CMID use Windows wire order.
    pub fn new(
        application_id: [u8; 16],
        activation_id: [u8; 16],
        kms_id: [u8; 16],
        cmid: [u8; 16],
        time: u64,
    ) -> Self {
        Self {
            version: Version::V6,
            virtual_machine: false,
            license_status: 2,
            binding_expiration: 43200,
            application_id,
            activation_id,
            kms_id,
            cmid,
            required_count: 25,
            time,
            previous_cmid: [0; 16],
            workstation: "WORKSTATION".into(),
        }
    }

    /// Serializes a request with a fresh cryptographically random salt.
    /// Retains the data needed to verify its response.
    pub fn encode(&self, salt: [u8; 16]) -> Result<EncodedRequest, Error> {
        if self.workstation.contains('\0') || self.workstation.encode_utf16().count() > 63 {
            return Err(Error::Config(
                "workstation must have at most 63 UTF-16 units and no NUL",
            ));
        }
        let mut base = Vec::with_capacity(236);
        base.extend_from_slice(&self.version.wire());
        for value in [
            u32::from(self.virtual_machine),
            self.license_status,
            self.binding_expiration,
        ] {
            base.extend_from_slice(&value.to_le_bytes());
        }
        for guid in [
            self.application_id,
            self.activation_id,
            self.kms_id,
            self.cmid,
        ] {
            base.extend_from_slice(&guid);
        }
        base.extend_from_slice(&self.required_count.to_le_bytes());
        base.extend_from_slice(&self.time.to_le_bytes());
        base.extend_from_slice(&self.previous_cmid);
        for unit in self.workstation.encode_utf16() {
            base.extend_from_slice(&unit.to_le_bytes());
        }
        base.resize(236, 0);
        let bytes = if self.version == Version::V4 {
            base.extend_from_slice(&aes_cmac_v4(&base));
            base
        } else {
            let mut plain = salt.to_vec();
            plain.extend_from_slice(&base);
            plain.extend_from_slice(&[4; 4]);
            let blocks = plain.as_chunks_mut::<16>().0;
            if self.version == Version::V5 {
                aes_encrypt_cbc_blocks(&cipher_v5(), None, blocks);
            } else {
                aes_encrypt_cbc_blocks(&cipher_v6(), None, blocks);
            }
            [self.version.wire().as_slice(), &plain].concat()
        };
        Ok(EncodedRequest {
            bytes,
            version: self.version,
            cmid: self.cmid,
            time: self.time,
            salt,
        })
    }
}

/// Protected request and private response-verification context.
pub struct EncodedRequest {
    bytes: Vec<u8>,
    version: Version,
    cmid: [u8; 16],
    time: u64,
    salt: [u8; 16],
}

/// A response whose integrity, CMID, timestamp and version have been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationResponse {
    /// Protocol generation.
    pub version: Version,
    /// Server extended product ID.
    pub epid: String,
    /// Reported client count.
    pub client_count: u32,
    /// Activation retry interval in minutes.
    pub activation_interval: u32,
    /// Renewal interval in minutes.
    pub renewal_interval: u32,
    /// Host hardware identity, present only in V6.
    pub hardware_id: Option<[u8; 8]>,
}

impl EncodedRequest {
    /// Encoded KMS request bytes for the RPC operation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Decrypts and validates a complete response, including its integrity fields.
    pub fn verify_response(&self, bytes: &[u8]) -> Result<ActivationResponse, Error> {
        if bytes.len() > 512 || bytes.len() < 4 || bytes[..4] != self.version.wire() {
            return Err(Error::Protocol("invalid response size or version"));
        }
        let mut plain = Vec::new();
        let base = if self.version == Version::V4 {
            if bytes.len() < 16 {
                return Err(Error::Protocol("short V4 response"));
            }
            let (base, mac) = bytes.split_at(bytes.len() - 16);
            if !bool::from(aes_cmac_v4(base).ct_eq(mac)) {
                return Err(Error::Protocol("invalid V4 response MAC"));
            }
            base
        } else {
            if bytes.len() < 36 || !(bytes.len() - 4).is_multiple_of(16) {
                return Err(Error::Protocol("invalid encrypted response size"));
            }
            let mut decoded = bytes[4..].to_vec();
            if self.version == Version::V5 {
                aes_decrypt_cbc(&cipher_v5(), None, &mut decoded);
            } else {
                aes_decrypt_cbc(&cipher_v6(), None, &mut decoded);
            }
            let padding = usize::from(*decoded.last().ok_or(Error::Protocol("missing padding"))?);
            if !(1..=16).contains(&padding)
                || !decoded[decoded.len() - padding..]
                    .iter()
                    .all(|b| usize::from(*b) == padding)
            {
                return Err(Error::Protocol("invalid response padding"));
            }
            decoded.truncate(decoded.len() - padding);
            if self.version == Version::V5 && decoded[..16] != self.salt {
                return Err(Error::Protocol("V5 response salt mismatch"));
            }
            plain = decoded;
            &plain[16..]
        };
        let mut input = Reader::new(base);
        if input.array::<4>()? != self.version.wire() {
            return Err(Error::Protocol("inner response version mismatch"));
        }
        let size = input.u32()? as usize;
        if !(4..=128).contains(&size) || !size.is_multiple_of(2) {
            return Err(Error::Protocol("invalid ePID length"));
        }
        let pid = input.take(size)?;
        let units: Vec<u16> = pid
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
            return Err(Error::Protocol("invalid ePID terminator"));
        }
        let epid = String::from_utf16(&units[..units.len() - 1])
            .map_err(|_| Error::Protocol("invalid ePID UTF-16"))?;
        if input.array::<16>()? != self.cmid || input.u64()? != self.time {
            return Err(Error::Protocol("response CMID or timestamp mismatch"));
        }
        let mut response = ActivationResponse {
            version: self.version,
            epid,
            client_count: input.u32()?,
            activation_interval: input.u32()?,
            renewal_interval: input.u32()?,
            hardware_id: None,
        };
        if self.version != Version::V4 {
            let mut random = input.array::<16>()?;
            xor_block(&mut random, &self.salt);
            if !bool::from(Sha256::digest(random).as_slice().ct_eq(input.take(32)?)) {
                return Err(Error::Protocol("invalid response salt hash"));
            }
            if self.version == Version::V6 {
                response.hardware_id = Some(input.array()?);
                if input.array::<16>()? != self.salt {
                    return Err(Error::Protocol("V6 response salt mismatch"));
                }
                let received = input.take(16)?;
                // Accept adjacent time slots, as the reference protocol allows.
                let valid = [-1i64, 0, 1].into_iter().any(|offset| {
                    let slot = (self.time / 0x00000022816889bd)
                        .wrapping_add_signed(offset)
                        .wrapping_mul(0x000000208cbab5ed)
                        .wrapping_add(0x3156cd5ac628477a);
                    let hash = Sha256::digest(slot.to_le_bytes());
                    let mut mac =
                        Hmac::<Sha256>::new_from_slice(&hash[16..]).expect("fixed HMAC key size");
                    // Include the decrypted IV, base and V6 fields, excluding the HMAC.
                    let signed_len = 16 + 44 + size + 48 + 8 + 16;
                    mac.update(&plain[..signed_len]);
                    bool::from(mac.finalize().into_bytes()[16..].ct_eq(received))
                });
                if !valid {
                    return Err(Error::Protocol("invalid V6 response HMAC"));
                }
            }
        }
        input.finish()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostConfig, PreparedHost, respond_into};

    fn fixture_request(version: Version, wire: &[u8]) -> (ActivationRequest, [u8; 16]) {
        let (base, salt) = if version == Version::V4 {
            (wire[..236].to_vec(), [0; 16])
        } else {
            let mut plain = wire[4..].to_vec();
            if version == Version::V5 {
                aes_decrypt_cbc(&cipher_v5(), None, &mut plain);
            } else {
                aes_decrypt_cbc(&cipher_v6(), None, &mut plain);
            }
            (plain[16..252].to_vec(), plain[..16].try_into().unwrap())
        };
        let mut request = ActivationRequest::new(
            base[16..32].try_into().unwrap(),
            base[32..48].try_into().unwrap(),
            base[48..64].try_into().unwrap(),
            base[64..80].try_into().unwrap(),
            u64::from_le_bytes(base[84..92].try_into().unwrap()),
        );
        request.version = version;
        request.workstation = "TEST-PC".into();
        (request, salt)
    }

    #[test]
    fn generated_requests_match_independent_python_fixtures() {
        for (version, wire) in [
            (
                Version::V4,
                include_bytes!("../../../tests/fixtures/v4-request.bin").as_slice(),
            ),
            (
                Version::V5,
                include_bytes!("../../../tests/fixtures/v5-request.bin").as_slice(),
            ),
            (
                Version::V6,
                include_bytes!("../../../tests/fixtures/v6-request.bin").as_slice(),
            ),
        ] {
            let (request, salt) = fixture_request(version, wire);
            let encoded = request.encode(salt).unwrap();
            assert_eq!(encoded.as_bytes(), wire);
            let response = match version {
                Version::V4 => include_bytes!("../../../tests/fixtures/v4-response.bin").as_slice(),
                Version::V5 => include_bytes!("../../../tests/fixtures/v5-response.bin").as_slice(),
                Version::V6 => include_bytes!("../../../tests/fixtures/v6-response.bin").as_slice(),
            };
            assert_eq!(
                encoded.verify_response(response).unwrap().epid,
                HostConfig::default().epid
            );
        }
    }

    #[test]
    fn all_versions_verify_and_reject_corruption_truncation_and_replay() {
        for version in [Version::V4, Version::V5, Version::V6] {
            let mut request =
                ActivationRequest::new([1; 16], [2; 16], [3; 16], [4; 16], 133444736000000000);
            request.version = version;
            let encoded = request.encode([5; 16]).unwrap();
            let host = HostConfig {
                epid: "😀-host".into(),
                ..HostConfig::default()
            };
            let mut response = Vec::new();
            respond_into(
                encoded.as_bytes(),
                &PreparedHost::new(&host).unwrap(),
                &mut response,
                [6; 16],
                [7; 16],
            )
            .unwrap();
            let verified = encoded.verify_response(&response).unwrap();
            assert_eq!(verified.epid, host.epid);
            assert_eq!(
                verified.hardware_id,
                if version == Version::V6 {
                    Some(host.hardware_id)
                } else {
                    None
                }
            );
            for length in 0..response.len() {
                assert!(
                    encoded.verify_response(&response[..length]).is_err(),
                    "{version:?} length {length}"
                );
            }
            for offset in 0..response.len() {
                let mut corrupt = response.clone();
                corrupt[offset] ^= 1;
                assert!(
                    encoded.verify_response(&corrupt).is_err(),
                    "{version:?} offset {offset}"
                );
            }
            request.cmid[0] ^= 1;
            assert!(
                request
                    .encode([5; 16])
                    .unwrap()
                    .verify_response(&response)
                    .is_err()
            );
            request.cmid[0] ^= 1;
            request.time += 1;
            assert!(
                request
                    .encode([5; 16])
                    .unwrap()
                    .verify_response(&response)
                    .is_err()
            );
        }
    }

    #[test]
    fn workstation_is_validated_without_truncating_surrogate_pairs() {
        let mut request = ActivationRequest::new([0; 16], [0; 16], [0; 16], [0; 16], 0);
        for name in ["x".repeat(64), "😀".repeat(32), "a\0b".into()] {
            request.workstation = name;
            assert!(request.encode([0; 16]).is_err());
        }
        request.workstation = "😀".repeat(31);
        assert!(request.encode([0; 16]).is_ok());
    }
}
