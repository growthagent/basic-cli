use roc_std::{RocList, RocResult, RocStr};

#[repr(C)]
pub struct AesGcmEncryptResult {
    pub auth_tag: RocList<u8>,
    pub ciphertext: RocList<u8>,
}

/// Derives a cryptographic key from a password using PBKDF2-HMAC-SHA256.
///
/// PBKDF2 (Password-Based Key Derivation Function 2) applies a pseudorandom function
/// (HMAC-SHA256) repeatedly to derive a key of specified length. The iteration count
/// makes brute-force attacks computationally expensive.
///
/// # Parameters
/// - `password`: The password or secret to derive a key from
/// - `salt`: A unique salt (should be randomly generated for each use, minimum 16 bytes recommended)
/// - `iterations`: Number of iterations (higher = slower but more secure)
/// - `key_length`: The desired output key length in bytes
///
/// # Security Recommendations
/// - **Iterations**: OWASP recommends 600,000+ iterations for PBKDF2-HMAC-SHA256 (as of 2023).
///   Lower values may be appropriate for non-security-critical uses or resource-constrained
///   environments, but values below 10,000 offer minimal protection against brute-force attacks.
/// - **Salt**: Use at least 16 bytes of cryptographically random data (see `random_bytes`).
///   Never reuse salts across different passwords.
/// - **Key length**: Typically 32 bytes for AES-256, 64 bytes for HMAC-SHA512 keys.
///   Values over 1024 bytes are unusual and may indicate a design issue.
///
/// # Common Use Cases
/// - Deriving encryption keys from user passwords
/// - Key stretching to make weak passwords stronger
/// - Converting text secrets into fixed-length cryptographic keys
pub fn pbkdf2_hmac_sha256(password: &RocList<u8>, salt: &RocList<u8>, iterations: u32, key_length: u32) -> RocList<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut secret = vec![0u8; key_length as usize];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut secret);
    secret.as_slice().into()
}

/// Decrypts ciphertext encrypted with AES256-GCM.
///
/// # Parameters
/// - `ciphertext`: The encrypted data (without nonce or auth tag)
/// - `key`: Must be exactly 32 bytes
/// - `nonce`: Must be exactly 12 bytes (the same nonce used during encryption)
/// - `auth_tag`: Must be exactly 16 bytes (as returned by encrypt)
///
/// # Returns
/// On success, returns the decrypted plaintext. Returns an error if the key, nonce,
/// or auth_tag have invalid lengths, or if authentication fails (wrong key, corrupted
/// ciphertext, or tampered data).
pub fn decrypt_aes256_gcm(ciphertext: &RocList<u8>, key: &RocList<u8>, nonce: &RocList<u8>, auth_tag: &RocList<u8>) -> RocResult<RocList<u8>, RocStr> {
    use aes_gcm::{aead::KeyInit, aead::Aead, Aes256Gcm, Nonce, Tag};

    if key.len() != 32 {
        return RocResult::err(RocStr::from("Key must be 32 bytes for AES-256-GCM"));
    }
    if nonce.len() != 12 {
        return RocResult::err(RocStr::from("Nonce must be 12 bytes for AES-256-GCM"));
    }
    if auth_tag.len() != 16 {
        return RocResult::err(RocStr::from("Auth tag must be 16 bytes for AES-256-GCM"));
    }

    match Aes256Gcm::new_from_slice(&key) {
        Ok(aes) => {
            let nonce: &Nonce<sha2::digest::consts::U12> = Nonce::from_slice(&nonce);
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
            RocResult::err(format!("Aes256Gcm::new_from_slice failed: {:#?}", e).as_str().into())
        },
    }
}

/// Encrypts plaintext with AES256-GCM.
///
/// **Critical**: Never reuse a nonce with the same key. Reusing a (key, nonce) pair
/// completely breaks AES-GCM's security, allowing attackers to decrypt messages and
/// forge valid ciphertexts.
///
/// # Parameters
/// - `plaintext`: The data to encrypt
/// - `key`: Must be exactly 32 bytes
/// - `nonce`: Must be exactly 12 bytes and unique per encryption with the same key
///
/// # Returns
/// On success, returns the ciphertext and a 16-byte authentication tag.
pub fn encrypt_aes256_gcm(plaintext: &RocList<u8>, key: &RocList<u8>, nonce: &RocList<u8>) -> RocResult<AesGcmEncryptResult, RocStr> {
    use aes_gcm::{aead::AeadInPlace, aead::KeyInit, Aes256Gcm, Key, Nonce};
    use std::convert::TryInto;

    if key.len() != 32 {
        return RocResult::err(RocStr::from("Key must be 32 bytes for AES-256-GCM"));
    }
    if nonce.len() != 12 {
        return RocResult::err(RocStr::from("Nonce must be 12 bytes for AES-256-GCM"));
    }

    let key_array: [u8; 32] = key.as_slice().try_into().unwrap();
    let key = Key::<Aes256Gcm>::from_slice(&key_array);
    let nonce_array: [u8; 12] = nonce.as_slice().try_into().unwrap();
    let nonce: &Nonce<sha2::digest::consts::U12> = Nonce::from_slice(&nonce_array);

    let cipher = Aes256Gcm::new(key);

    // Create a buffer with the plaintext that will be encrypted in place
    let mut buffer = plaintext.as_slice().to_vec();

    // Use encrypt_in_place_detached to get the auth tag separately
    match cipher.encrypt_in_place_detached(nonce, b"", &mut buffer) {
        Ok(tag) => {
            // buffer now contains the ciphertext, tag is the auth tag (16 bytes for GCM)
            let auth_tag = RocList::from(tag.as_slice());
            let ciphertext = RocList::from(buffer.as_slice());

            RocResult::ok(AesGcmEncryptResult { auth_tag, ciphertext })
        }
        Err(e) => RocResult::err(RocStr::from(format!("Encryption failed: {:#?}", e).as_str())),
    }
}

/// Generates cryptographically secure random bytes using the OS random number generator.
///
/// Uses `OsRng` which provides cryptographically strong random numbers suitable for
/// security-sensitive operations like generating encryption keys, nonces, and tokens.
pub fn random_bytes(length: u32) -> RocResult<RocList<u8>, RocStr> {
    use rand::RngCore;

    let mut bytes = vec![0u8; length as usize];
    match rand::rngs::OsRng.try_fill_bytes(&mut bytes) {
        Ok(()) => RocResult::ok(RocList::from(bytes.as_slice())),
        Err(e) => RocResult::err(RocStr::from(format!("Failed to generate random bytes: {:#?}", e).as_str())),
    }
}

/// Hashes a password using bcrypt.
///
/// # Parameters
/// - `password`: The password to hash
/// - `cost`: Work factor between 4 and 31 (inclusive). Higher values are slower but more secure.
///   Recommended values: 10-14 for most applications, with 12 being a good default.
///   Each increment doubles the computation time.
///
/// # Security Recommendations
/// - Cost 10: ~100ms on modern hardware (minimum for production)
/// - Cost 12: ~400ms (good default)
/// - Cost 14: ~1.6s (high security)
/// - Values below 10 are generally considered insufficient for password storage.
pub fn bcrypt_hash(password: &RocList<u8>, cost: u32) -> RocResult<RocStr, RocStr> {
    if cost < 4 || cost > 31 {
        return RocResult::err(RocStr::from(format!("Bcrypt cost must be between 4 and 31, got: {}", cost).as_str()));
    }

    match bcrypt::hash(password.as_slice(), cost) {
        Ok(hash_str) => RocResult::ok(RocStr::from(hash_str.as_str())),
        Err(e) => RocResult::err(RocStr::from(format!("Bcrypt hash failed: {:#?}", e).as_str())),
    }
}

/// Verifies a password against a bcrypt hash.
pub fn bcrypt_verify(password: &RocList<u8>, hash: &RocStr) -> RocResult<bool, RocStr> {
    match bcrypt::verify(password.as_slice(), hash.as_str()) {
        Ok(is_valid) => RocResult::ok(is_valid),
        Err(e) => RocResult::err(RocStr::from(format!("Bcrypt verify failed: {:#?}", e).as_str())),
    }
}
