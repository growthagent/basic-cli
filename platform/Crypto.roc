# NOTE: We probably want to split this into several (sub-)modules as we add more functionality and
# a natural structure becomes apparent.
module [
  bcrypt_hash!,
  bcrypt_verify!,
  decrypt_aes256_gcm!,
  encrypt_aes256_gcm!,
  pbkdf2_hmac_sha256!,
  random_bytes!,
]

import Host

## Decrypt a ciphertext encrypted with AES256-GCM.
decrypt_aes256_gcm! : { ciphertext : List U8, key : List U8, nonce: List U8, auth_tag : List U8 } => Result (List U8) Str
decrypt_aes256_gcm! = |{ ciphertext, key, nonce, auth_tag }|
  Host.decrypt_aes256_gcm!(
    ciphertext,
    key,
    nonce,
    auth_tag,
  )

# expect
#     input = {
#       ciphertext: Str.to_utf8("Hello, Roc!"),
#       key: Str.to_utf8("secret-key-that-is-32-chars-long"),
#       nonce: Str.to_utf8("some-iv-16-chars"),
#       auth_tag: Str.to_utf8("some-authtag"),
#     }
# 
#     expected = Ok(Str.to_utf8("3f2661801ba8d6f0870451b85ebc1c25c1a7acbc89af22"))
# 
#     expected == decrypt_aes256_gcm(input)

## Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.
##
## PBKDF2 repeatedly applies HMAC-SHA256 to derive a key of specified length.
## The iteration count makes brute-force attacks computationally expensive.
##
## Parameters:
## - `password`: The password or secret to derive a key from
## - `salt`: A unique salt (use `random_bytes!` to generate)
## - `iterations`: Number of iterations (OWASP recommends 600,000+ as of 2023)
## - `key_length`: Desired output key length in bytes (typically 32 for AES-256)
##
## Common use cases:
## - Deriving encryption keys from user passwords
## - Converting text secrets into fixed-length cryptographic keys
pbkdf2_hmac_sha256! : { password : List U8, salt : List U8, iterations: U32, key_length: U32 } => List U8
pbkdf2_hmac_sha256! = |{password, salt, iterations, key_length}| Host.pbkdf2_hmac_sha256!(
    password,
    salt,
    iterations,
    key_length,
  )

## Encrypt plaintext using AES256-GCM.
encrypt_aes256_gcm! : { plaintext : List U8, key : List U8, nonce: List U8 } => Result { ciphertext : List U8, auth_tag : List U8 } Str
encrypt_aes256_gcm! = |{ plaintext, key, nonce }|
  Host.encrypt_aes256_gcm!(plaintext, key, nonce)

## Generate cryptographically secure random bytes.
random_bytes! : U32 => Result (List U8) Str
random_bytes! = |length|
  Host.random_bytes!(length)

## Hash a password using bcrypt with the specified cost factor.
bcrypt_hash! : List U8, U32 => Result (List U8) Str
bcrypt_hash! = |password, cost|
  Host.bcrypt_hash!(password, cost)

## Verify a password against a bcrypt hash.
bcrypt_verify! : List U8, Str => Result Bool Str
bcrypt_verify! = |password, hash|
  Host.bcrypt_verify!(password, hash)
