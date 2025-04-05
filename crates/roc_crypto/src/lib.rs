//! This crate provides common functionality for Roc to interface with cryptography crates
use roc_std::{RocList, RocResult, RocStr};

pub fn pbkdf2_hmac_sha256(password: &RocList<u8>, salt: &RocList<u8>, iterations: u32, key_length: u32) -> RocList<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut secret = vec![0u8; key_length as usize];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut secret);
    secret.as_slice().into()
}

// TODO: Better error than a RocStr
pub fn decrypt_aes256_gcm(ciphertext: &RocList<u8>, key: &RocList<u8>, nonce: &RocList<u8>, auth_tag: &RocList<u8>) -> RocResult<RocList<u8>, RocStr> {
    use aes_gcm::{aead::KeyInit, aead::Aead, Aes256Gcm, Nonce, Tag};

    match Aes256Gcm::new_from_slice(&key) {
        Ok(aes) => {
            // AES-GCM expects a 12-byte nonce
            let nonce: &Nonce<sha2::digest::consts::U12> = Nonce::from_slice(&nonce);

            // AES-GCM expects a 16-byte tag
            let tag: &Tag<sha2::digest::consts::U16> = Tag::from_slice(&auth_tag);

            let mut buffer = Vec::with_capacity(ciphertext.len() + auth_tag.len());
            buffer.extend_from_slice(&ciphertext);
            buffer.extend_from_slice(tag);

            match aes.decrypt(nonce, buffer.as_slice()) {
                Ok(decrypted) => RocResult::ok(decrypted.as_slice().into()),
                Err(e) => RocResult::err(format!("Aes256Gcm::decrypt failed: {:#?}", e).as_str().into()),
            }
        },
        Err(e) => {
            RocResult::err(format!("Aes256Gcm::new_from_slice failed: {:?}", e).as_str().into())
        },
    }
}
