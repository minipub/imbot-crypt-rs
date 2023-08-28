use base64;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};

use aes;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc;
use sha1::{Digest, Sha1};

use anyhow::{anyhow, Result as AnyRs};
use thiserror::Error;

use byteorder::{BigEndian, WriteBytesExt};
use rand::Rng;
use std::io::Write;

const LETTER_BYTES: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const BLOCK_SIZE: usize = 32;

#[derive(Error, Debug)]
enum CryptError {
    #[error("invalid signature (expect: {0}, found: {1})")]
    ValidateSignatureError(String, String),

    #[error("AES key encrypt error (key: {0:?}, enc_data: {1:?}, error: {2})")]
    AesEncryptError(Vec<u8>, Vec<u8>, String),

    #[error("AES key decrypt error (key: {0:?}, enc_data: {1:?}, error: {2})")]
    AesDecryptError(Vec<u8>, Vec<u8>, String),

    #[error("b64decode error (enc_data: {0}, error: {1})")]
    Base64DecodeError(String, String),

    #[error("pkcs7 padding error (text: {0:?}, error: {1})")]
    Pkcs7PadError(Vec<u8>, String),

    #[error("pkcs7 unpadding error (text: {0:?}, error: {1})")]
    Pkcs7UnpadError(Vec<u8>, String),

    #[error("utf8-str conversion error (vec: {0:?}, error: {1})")]
    Utf8StringConvError(Vec<u8>, String),

    #[error("Random String error (error: {0})")]
    RandomStringError(String),

    #[error("Write Bytes in order error (error: {0})")]
    WriteBytesError(String),
}

#[derive(Debug)]
struct WxWork<'a> {
    corp_id: &'a str,
    token: &'a str,
    enc_aes_key: &'a str,
    aes_key: Vec<u8>,
}

impl<'a> WxWork<'a> {
    pub fn new(corp_id: &'a str, token: &'a str, enc_aes_key: &'a str) -> Result<Self, CryptError> {
        let aes_key = WxWork::decode_aes_key(enc_aes_key)
            .map_err(|e| CryptError::Base64DecodeError(enc_aes_key.to_string(), e.to_string()))?;
        Ok(WxWork {
            corp_id,
            token,
            enc_aes_key,
            aes_key,
        })
    }

    fn decode_aes_key(enc_aes_key: &str) -> AnyRs<Vec<u8>> {
        let mut encoding_aes_key = String::from(enc_aes_key);
        encoding_aes_key.push('=');
        base64_decode(&encoding_aes_key)
    }

    pub fn get_sign(&self, timestamp: &str, nonce: &str, data: &str) -> String {
        // Sort the parameters in dictionary order and concatenate them into a single string.
        let mut params = vec![
            ("token", self.token),
            ("timestamp", timestamp),
            ("nonce", nonce),
            ("msg_encrypt", data),
        ];
        params.sort_by(|a, b| a.1.cmp(b.1));
        let sorted_params: String = params
            .iter()
            .map(|(_key, value)| format!("{}", value))
            .collect();

        // println!("sorted_params: {}", sorted_params);

        // Calculate the SHA1 hash of the sorted parameters string.
        let mut hasher = Sha1::new();
        hasher.update(sorted_params.as_bytes());
        let sha1_hash = hasher.finalize();

        // Convert the SHA1 hash to a hexadecimal string.
        let signature_calculated = format!("{:x}", sha1_hash);
        signature_calculated
    }

    pub fn decrypt(
        &self,
        timestamp: &str,
        nonce: &str,
        signature: &str,
        data: &str,
    ) -> Result<String, CryptError> {
        let signature_calculated = self.get_sign(timestamp, nonce, data);

        // Compare the calculated signature with the provided signature.
        if signature_calculated != signature {
            return Err(CryptError::ValidateSignatureError(
                signature.to_string(),
                signature_calculated,
            ));
        }

        // Decode the base64-encoded AES message.
        let aes_msg = base64_decode(data)
            .map_err(|e| CryptError::Base64DecodeError(data.to_string(), e.to_string()))?;
        // println!("aes_msg: {:?}", aes_msg);
        // println!("aes_msg_cnt: {:?}", aes_msg.len());
        // println!("aes_key: {:?}", &self.aes_key);

        // Decrypt the AES message using the AES key.
        let mut rand_msg = aes_decrypt(&aes_msg, &self.aes_key).map_err(|e| {
            CryptError::AesDecryptError(self.aes_key.clone(), aes_msg.clone(), e.to_string())
        })?;

        let rand_msg = match pkcs7_unpadding(&mut rand_msg, BLOCK_SIZE) {
            Ok(rs) => rs,
            Err(e) => {
                return Err(CryptError::Pkcs7UnpadError(rand_msg, e.to_string()))?;
            }
        };

        // Get the content by removing the first 16 random bytes.
        let content = &rand_msg[16..];

        // Get the message length (4 bytes) and convert it to an unsigned integer.
        let msg_len_bytes = &content[..4];
        let msg_len = str_to_uint(msg_len_bytes) as usize;

        // Extract the message (from index 4 to msg_len+4).
        let msg = &content[4..(msg_len + 4)];

        // The remaining bytes after the message are assigned to `receiveid`.
        let receiveid = &content[(msg_len + 4)..];
        println!("Receiveid: {:?}", std::str::from_utf8(&receiveid).unwrap());

        // std::str::from_utf8(&msg).unwrap()

        String::from_utf8(msg.to_vec())
            .map_err(|e| CryptError::Utf8StringConvError(msg.to_vec(), e.to_string()))
    }

    pub fn encrypt(
        &self,
        timestamp: &str,
        nonce: &str,
        reply_msg: String,
    ) -> Result<String, CryptError> {
        let rand_str = rand_str(16).map_err(|e| CryptError::RandomStringError(e.to_string()))?;

        let mut buffer = Vec::new();
        buffer.extend_from_slice(rand_str.as_bytes());

        let mut msg_len_buf = vec![0; 4];
        (&mut msg_len_buf[..])
            .write_u32::<BigEndian>(reply_msg.len() as u32)
            .map_err(|e| CryptError::WriteBytesError(e.to_string()))?;

        buffer.extend_from_slice(&msg_len_buf);
        buffer.extend_from_slice(reply_msg.as_bytes());
        buffer.extend_from_slice(self.corp_id.as_bytes());

        let pad_msg = pkcs7_padding(&buffer, BLOCK_SIZE)
            .map_err(|e| CryptError::Pkcs7PadError(buffer, e.to_string()))?;

        let ciphertext = aes_encrypt(&pad_msg, &self.aes_key).map_err(|e| {
            CryptError::AesEncryptError(self.aes_key.clone(), pad_msg.clone(), e.to_string())
        })?;

        let ciphertext = base64_encode(ciphertext);

        let signature = self.get_sign(timestamp, nonce, &ciphertext);

        Ok(format!("<xml><Encrypt><![CDATA[{}]]></Encrypt><MsgSignature><![CDATA[{}]]></MsgSignature><TimeStamp>{}</TimeStamp><Nonce><![CDATA[{}]]></Nonce></xml>", ciphertext, signature, timestamp, nonce))
    }
}

fn aes_encrypt(plaintext: &[u8], key: &[u8]) -> AnyRs<Vec<u8>> {
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut iv: [u8; 16] = [0; 16];
    iv.copy_from_slice(&key[..16]);

    let mut buf = vec![0u8; plaintext.len()];

    let ciphertext = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<NoPadding>(&plaintext, &mut buf)
        .map_err(|e| anyhow!(e))?;
    Ok(ciphertext.to_vec())
}

fn aes_decrypt(encrypted_data: &[u8], key: &[u8]) -> AnyRs<Vec<u8>> {
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut iv: [u8; 16] = [0; 16];
    iv.copy_from_slice(&key[..16]);

    let mut buf = vec![0u8; encrypted_data.len()];

    // println!("key: {:?}", key);
    // println!("iv: {:?}", iv);
    // println!("encrypted_data: {:?}", encrypted_data);

    let plaintext = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<NoPadding>(&encrypted_data, &mut buf)
        .map_err(|e| anyhow!(e))?;
    Ok(plaintext.to_vec())
}

fn pkcs7_padding(plaintext: &Vec<u8>, block_size: usize) -> AnyRs<Vec<u8>> {
    let padding = block_size - (plaintext.len() % block_size);
    let padtext = vec![padding as u8; padding];
    let mut buffer = Vec::with_capacity(plaintext.len() + padding);

    buffer.write_all(&plaintext)?;
    buffer.write_all(&padtext)?;

    Ok(buffer)
}

fn pkcs7_unpadding<'a>(plaintext: &'a mut Vec<u8>, block_size: usize) -> AnyRs<&'a Vec<u8>> {
    let plaintext_len = plaintext.len();

    if plaintext.is_empty() || plaintext_len == 0 {
        return Err(anyhow!("pKCS7Unpadding error nil or zero"));
    }

    if plaintext_len % block_size != 0 {
        return Err(anyhow!(
            "pKCS7Unpadding text not a multiple of the block size"
        ));
    }

    let padding_len = plaintext[plaintext_len - 1] as usize;
    if padding_len > block_size || padding_len == 0 {
        return Err(anyhow!("pKCS7Unpadding invalid padding length"));
    }

    plaintext.truncate(plaintext_len - padding_len);
    Ok(plaintext)
}

fn base64_encode(vs: Vec<u8>) -> String {
    engine::GeneralPurpose::new(
        &alphabet::STANDARD,
        general_purpose::PAD.with_decode_allow_trailing_bits(true),
    )
    .encode(vs)
}

fn base64_decode(s: &str) -> AnyRs<Vec<u8>> {
    let bytes = engine::GeneralPurpose::new(
        &alphabet::STANDARD,
        general_purpose::PAD.with_decode_allow_trailing_bits(true),
    )
    .decode(s)?;
    Ok(bytes)
}

// Function to convert the first 4 bytes of a slice into an unsigned integer.
fn str_to_uint(slice: &[u8]) -> u32 {
    ((slice[0] as u32) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | (slice[3] as u32)
}

fn rand_str(n: usize) -> AnyRs<String> {
    let mut rng = rand::thread_rng();

    let mut vs = Vec::with_capacity(n);
    for _ in 0..n {
        let idx = rng.gen_range(0..LETTER_BYTES.len());
        vs.push(LETTER_BYTES[idx]);
    }

    Ok(String::from_utf8(vs)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // let result = add(2, 2);
        // assert_eq!(result, 4);
    }
}
