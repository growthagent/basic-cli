# NOTE: We probably want to split this into several (sub-)modules as we add more functionality and
# a natural structure becomes apparent.
module [
  decrypt_aes256_gcm,
  pbkdf2_hmac_sha256,
]

import Host

## Decrypt a ciphertext encrypted with AES256-GCM.
decrypt_aes256_gcm : { ciphertext : List U8, key : List U8, nonce: List U8, auth_tag : List U8 } -> Result (List U8) Str
decrypt_aes256_gcm = |{ ciphertext, key, nonce, auth_tag }|
  Host.decrypt_aes256_gcm(
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

pbkdf2_hmac_sha256 : { password : List U8, salt : List U8, iterations: U32, key_length: U32 } -> List U8
pbkdf2_hmac_sha256 = |{password, salt, iterations, key_length}| Host.pbkdf2_hmac_sha256(
    password,
    salt,
    iterations,
    key_length,
  )
