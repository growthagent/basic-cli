app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Crypto
import pf.File
import pf.Arg exposing [Arg]

# Tests Crypto module functions: random_bytes, bcrypt, AES-256-GCM, PBKDF2,
# and hash functions (hash!, hash_file!, hash_file_chunks!).

main! : List Arg => Result {} _
main! = |_args|
    Stdout.line!("Testing Crypto module functions...")?

    test_random_bytes!({})?
    test_pbkdf2!({})?
    test_bcrypt!({})?
    test_aes_encryption!({})?
    test_aes_roundtrip!({})?
    test_aes_error_cases!({})?
    test_hash!({})?
    test_hash_file!({})?
    test_hash_file_chunks!({})?

    Stdout.line!("\nAll tests passed.")

test_random_bytes! : {} => Result {} _
test_random_bytes! = |{}|
    Stdout.line!("\nTesting Crypto.random_bytes!:")?

    # Test correct length
    bytes1 = Crypto.random_bytes!(16) |> Result.map_err(|err| FailedExpectation("random_bytes! failed: ${err}"))?
    if List.len(bytes1) != 16 then
        Err(FailedExpectation(
            """
            random_bytes! length:
            - Expected: 16
            - Got: ${Inspect.to_str(List.len(bytes1))}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Generated 16 random bytes")?

    # Test randomness - two calls should produce different results
    bytes2 = Crypto.random_bytes!(16) |> Result.map_err(|err| FailedExpectation("random_bytes! failed: ${err}"))?
    if bytes1 == bytes2 then
        Err(FailedExpectation(
            """
            random_bytes! randomness:
            - Expected: two different values
            - Got: same value twice
            """
        ))?
    else
        {}
    Stdout.line!("✓ Two calls produce different results")?

    # Test zero length
    bytes_zero = Crypto.random_bytes!(0) |> Result.map_err(|err| FailedExpectation("random_bytes!(0) failed: ${err}"))?
    if List.len(bytes_zero) != 0 then
        Err(FailedExpectation(
            """
            random_bytes!(0) length:
            - Expected: 0
            - Got: ${Inspect.to_str(List.len(bytes_zero))}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Zero length returns empty list")?

    # Test larger output (1024 bytes)
    bytes_large = Crypto.random_bytes!(1024) |> Result.map_err(|err| FailedExpectation("random_bytes!(1024) failed: ${err}"))?
    if List.len(bytes_large) != 1024 then
        Err(FailedExpectation(
            """
            random_bytes!(1024) length:
            - Expected: 1024
            - Got: ${Inspect.to_str(List.len(bytes_large))}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Large output (1024 bytes) works correctly")

test_pbkdf2! : {} => Result {} _
test_pbkdf2! = |{}|
    Stdout.line!("\nTesting Crypto.pbkdf2_hmac_sha256!:")?

    password = Str.to_utf8("password")
    salt = Str.to_utf8("salt")

    # Test against known test vector (PBKDF2-HMAC-SHA256)
    # From https://github.com/brycx/Test-Vector-Generation/blob/master/PBKDF2/pbkdf2-hmac-sha2-test-vectors.md
    # Password: "password", Salt: "salt", Iterations: 1, Key Length: 20
    # Expected: 120fb6cffcf8b32c43e7225256c4f837a86548c9
    expected_vector = [0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9]
    key_vector = Crypto.pbkdf2_hmac_sha256!({ password, salt, iterations: 1, key_length: 20 })
    if key_vector != expected_vector then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! test vector (iter=1, len=20):
            - Expected: ${Inspect.to_str(expected_vector)}
            - Got: ${Inspect.to_str(key_vector)}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Matches known test vector (iterations=1)")?

    # Test vector with more iterations
    # Password: "password", Salt: "salt", Iterations: 4096, Key Length: 20
    # Expected: c5e478d59288c841aa530db6845c4c8d962893a0
    expected_4096 = [0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0]
    key_4096 = Crypto.pbkdf2_hmac_sha256!({ password, salt, iterations: 4096, key_length: 20 })
    if key_4096 != expected_4096 then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! test vector (iter=4096, len=20):
            - Expected: ${Inspect.to_str(expected_4096)}
            - Got: ${Inspect.to_str(key_4096)}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Matches known test vector (iterations=4096)")?

    # Test correct output length
    key32 = Crypto.pbkdf2_hmac_sha256!({ password, salt, iterations: 1000, key_length: 32 })
    if List.len(key32) != 32 then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! key_length=32:
            - Expected length: 32
            - Got: ${Inspect.to_str(List.len(key32))}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Correct output length (32 bytes)")?

    # Test different key lengths
    key16 = Crypto.pbkdf2_hmac_sha256!({ password, salt, iterations: 1000, key_length: 16 })
    if List.len(key16) != 16 then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! key_length=16:
            - Expected length: 16
            - Got: ${Inspect.to_str(List.len(key16))}
            """
        ))?
    else
        {}
    Stdout.line!("✓ Correct output length (16 bytes)")?

    # Test determinism - same inputs produce same output
    key32_again = Crypto.pbkdf2_hmac_sha256!({ password, salt, iterations: 1000, key_length: 32 })
    if key32 != key32_again then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! determinism:
            - Expected: same output for same inputs
            - Got: different outputs
            """
        ))?
    else
        {}
    Stdout.line!("✓ Deterministic (same inputs → same output)")?

    # Test different salts produce different outputs
    salt2 = Str.to_utf8("different_salt")
    key_diff_salt = Crypto.pbkdf2_hmac_sha256!({ password, salt: salt2, iterations: 1000, key_length: 32 })
    if key32 == key_diff_salt then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! salt sensitivity:
            - Expected: different salt → different output
            - Got: same output
            """
        ))?
    else
        {}
    Stdout.line!("✓ Different salts produce different outputs")?

    # Test different passwords produce different outputs
    password2 = Str.to_utf8("different_password")
    key_diff_pass = Crypto.pbkdf2_hmac_sha256!({ password: password2, salt, iterations: 1000, key_length: 32 })
    if key32 == key_diff_pass then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! password sensitivity:
            - Expected: different password → different output
            - Got: same output
            """
        ))?
    else
        {}
    Stdout.line!("✓ Different passwords produce different outputs")?

    # Test different iteration counts produce different outputs
    key_diff_iter = Crypto.pbkdf2_hmac_sha256!({ password, salt, iterations: 2000, key_length: 32 })
    if key32 == key_diff_iter then
        Err(FailedExpectation(
            """
            pbkdf2_hmac_sha256! iteration sensitivity:
            - Expected: different iterations → different output
            - Got: same output
            """
        ))?
    else
        {}
    Stdout.line!("✓ Different iteration counts produce different outputs")

test_bcrypt! : {} => Result {} _
test_bcrypt! = |{}|
    Stdout.line!("\nTesting Crypto.bcrypt_hash! and bcrypt_verify!:")?

    # Test against known bcrypt hash (from bcrypt test vectors)
    # Password: "U*U*U" with cost 5 and salt "XXXXXXXXXXXXXXXXXXXXX."
    # From: https://github.com/openwall/john/issues/4388
    known_password = Str.to_utf8("U*U*U")
    known_hash = "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"
    when Crypto.bcrypt_verify!(known_password, known_hash) is
        Ok(is_valid) ->
            if is_valid then
                Stdout.line!("✓ Verified against known bcrypt hash")?
            else
                Err(FailedExpectation(
                    """
                    bcrypt_verify! known hash:
                    - Expected: Bool.true
                    - Got: Bool.false
                    """
                ))?
        Err(err) ->
            Err(FailedExpectation(
                """
                bcrypt_verify! known hash failed:
                - Expected: Ok(Bool)
                - Got: Err(${err})
                """
            ))?

    password = Str.to_utf8("my-secure-password-123")
    cost = 4  # Use minimum cost for faster tests

    when Crypto.bcrypt_hash!(password, cost) is
        Err(err) ->
            Err(FailedExpectation(
                """
                bcrypt_hash! failed:
                - Expected: Ok(List U8)
                - Got: Err(${err})
                """
            ))

        Ok(hash_str) ->
            # Validate bcrypt hash format: $2b$XX$... (60 characters total)
            # bcrypt hashes start with $2a$, $2b$, or $2y$ followed by cost
            hash_len = Str.count_utf8_bytes(hash_str)
            starts_correctly = Str.starts_with(hash_str, "$2")
            if hash_len != 60 then
                Err(FailedExpectation(
                    """
                    bcrypt_hash! format (length):
                    - Expected: 60 characters
                    - Got: ${Inspect.to_str(hash_len)} characters
                    """
                ))?
            else
                {}
            if !starts_correctly then
                Err(FailedExpectation(
                    """
                    bcrypt_hash! format (prefix):
                    - Expected: starts with "$2"
                    - Got: ${hash_str}
                    """
                ))?
            else
                {}
            Stdout.line!("✓ Password hashed with valid bcrypt format")?

            # Test that two hashes of same password differ (bcrypt uses random salt)
            when Crypto.bcrypt_hash!(password, cost) is
                Ok(hash2_str) ->
                    if hash_str == hash2_str then
                        Err(FailedExpectation(
                            """
                            bcrypt_hash! random salt:
                            - Expected: different hashes for same password (random salt)
                            - Got: identical hashes
                            """
                        ))?
                    else
                        {}
                    # Both hashes should still verify the same password
                    when Crypto.bcrypt_verify!(password, hash2_str) is
                        Ok(is_valid) ->
                            if is_valid then
                                Stdout.line!("✓ Same password produces different hashes (random salt)")?
                            else
                                Err(FailedExpectation(
                                    """
                                    bcrypt_verify! second hash:
                                    - Expected: Bool.true
                                    - Got: Bool.false
                                    """
                                ))?
                        Err(err) ->
                            Err(FailedExpectation(
                                """
                                bcrypt_verify! second hash failed:
                                - Expected: Ok(Bool)
                                - Got: Err(${err})
                                """
                            ))?
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        bcrypt_hash! second call failed:
                        - Expected: Ok(List U8)
                        - Got: Err(${err})
                        """
                    ))?

            # Test correct password
            when Crypto.bcrypt_verify!(password, hash_str) is
                Ok(is_valid) ->
                    if is_valid then
                        Stdout.line!("✓ Correct password verified successfully")?
                    else
                        Err(FailedExpectation(
                            """
                            bcrypt_verify! correct password:
                            - Expected: Bool.true
                            - Got: Bool.false
                            """
                        ))?
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        bcrypt_verify! failed:
                        - Expected: Ok(Bool)
                        - Got: Err(${err})
                        """
                    ))?

            # Test wrong password
            wrong_password = Str.to_utf8("wrong-password")
            when Crypto.bcrypt_verify!(wrong_password, hash_str) is
                Ok(is_valid) ->
                    if is_valid then
                        Err(FailedExpectation(
                            """
                            bcrypt_verify! wrong password:
                            - Expected: Bool.false
                            - Got: Bool.true
                            """
                        ))?
                    else
                        {}
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        bcrypt_verify! failed:
                        - Expected: Ok(Bool)
                        - Got: Err(${err})
                        """
                    ))?
            Stdout.line!("✓ Wrong password correctly rejected")?

            # Test empty password (should work - bcrypt handles empty passwords)
            empty_password = []
            when Crypto.bcrypt_hash!(empty_password, cost) is
                Ok(empty_hash_str) ->
                    when Crypto.bcrypt_verify!(empty_password, empty_hash_str) is
                        Ok(is_valid) ->
                            if is_valid then
                                Stdout.line!("✓ Empty password handled correctly")?
                            else
                                Err(FailedExpectation(
                                    """
                                    bcrypt empty password verify:
                                    - Expected: Bool.true
                                    - Got: Bool.false
                                    """
                                ))?
                        Err(err) ->
                            Err(FailedExpectation(
                                """
                                bcrypt_verify! empty password:
                                - Expected: Ok(Bool)
                                - Got: Err(${err})
                                """
                            ))?
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        bcrypt_hash! empty password:
                        - Expected: Ok(List U8)
                        - Got: Err(${err})
                        """
                    ))?

            # Test malformed hash string
            when Crypto.bcrypt_verify!(password, "not-a-valid-hash") is
                Err(_) ->
                    Stdout.line!("✓ Correctly rejected malformed hash")
                Ok(_) ->
                    Err(FailedExpectation(
                        """
                        bcrypt_verify! malformed hash:
                        - Expected: Err(_)
                        - Got: Ok(_)
                        """
                    ))

test_aes_encryption! : {} => Result {} _
test_aes_encryption! = |{}|
    Stdout.line!("\nTesting Crypto.encrypt_aes256_gcm!:")?

    # Test against NIST test vector (Test Case 14 from GCM spec)
    # From https://git.w1.fi/cgit/hostap/plain/tests/test-aes.c
    # Key: 00000000000000000000000000000000 00000000000000000000000000000000
    # IV: 000000000000000000000000
    # PT: 00000000000000000000000000000000
    # CT: cea7403d4d606b6e074ec5d3baf39d18
    # Tag: d0d1c8a799996bf0265b98b5d48ab919
    nist_key = List.repeat(0x00, 32)
    nist_nonce = List.repeat(0x00, 12)
    nist_plaintext = List.repeat(0x00, 16)
    nist_expected_ct = [0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18]
    nist_expected_tag = [0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19]

    when Crypto.encrypt_aes256_gcm!({ plaintext: nist_plaintext, key: nist_key, nonce: nist_nonce }) is
        Ok({ ciphertext: nist_ct, auth_tag: nist_tag }) ->
            if nist_ct != nist_expected_ct then
                Err(FailedExpectation(
                    """
                    encrypt_aes256_gcm! NIST test vector ciphertext:
                    - Expected: ${Inspect.to_str(nist_expected_ct)}
                    - Got: ${Inspect.to_str(nist_ct)}
                    """
                ))?
            else
                {}
            if nist_tag != nist_expected_tag then
                Err(FailedExpectation(
                    """
                    encrypt_aes256_gcm! NIST test vector auth_tag:
                    - Expected: ${Inspect.to_str(nist_expected_tag)}
                    - Got: ${Inspect.to_str(nist_tag)}
                    """
                ))?
            else
                {}
            Stdout.line!("✓ Matches NIST test vector (Test Case 14)")?
        Err(err) ->
            Err(FailedExpectation(
                """
                encrypt_aes256_gcm! NIST test vector failed:
                - Expected: Ok({ ciphertext, auth_tag })
                - Got: Err(${err})
                """
            ))?

    plaintext = Str.to_utf8("Hello, World!")
    key = List.repeat(0x42, 32)  # 32-byte key
    nonce = List.repeat(0x01, 12)  # 12-byte nonce

    when Crypto.encrypt_aes256_gcm!({ plaintext, key, nonce }) is
        Ok({ ciphertext, auth_tag }) ->
            # Verify output lengths
            ciphertext_ok = List.len(ciphertext) == List.len(plaintext)
            auth_tag_ok = List.len(auth_tag) == 16

            if ciphertext_ok && auth_tag_ok then
                Stdout.line!("✓ Encryption succeeded with correct output lengths")?
            else
                Err(FailedExpectation(
                    """
                    encrypt_aes256_gcm! output lengths:
                    - Expected: ciphertext=${Inspect.to_str(List.len(plaintext))}, auth_tag=16
                    - Got: ciphertext=${Inspect.to_str(List.len(ciphertext))}, auth_tag=${Inspect.to_str(List.len(auth_tag))}
                    """
                ))?

            # Test determinism - same inputs produce same output
            when Crypto.encrypt_aes256_gcm!({ plaintext, key, nonce }) is
                Ok({ ciphertext: ct2, auth_tag: tag2 }) ->
                    if ciphertext != ct2 || auth_tag != tag2 then
                        Err(FailedExpectation(
                            """
                            encrypt_aes256_gcm! determinism:
                            - Expected: same ciphertext and tag for same inputs
                            - Got: different outputs
                            """
                        ))?
                    else
                        {}
                    Stdout.line!("✓ Deterministic (same inputs → same output)")?
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        encrypt_aes256_gcm! determinism test failed:
                        - Got: Err(${err})
                        """
                    ))?

            # Test different nonces produce different ciphertext (critical security property)
            different_nonce = List.repeat(0x02, 12)
            when Crypto.encrypt_aes256_gcm!({ plaintext, key, nonce: different_nonce }) is
                Ok({ ciphertext: ct_diff_nonce, auth_tag: _ }) ->
                    if ciphertext == ct_diff_nonce then
                        Err(FailedExpectation(
                            """
                            encrypt_aes256_gcm! nonce sensitivity:
                            - Expected: different nonce → different ciphertext
                            - Got: same ciphertext (CRITICAL: nonce reuse vulnerability!)
                            """
                        ))?
                    else
                        {}
                    Stdout.line!("✓ Different nonces produce different ciphertext")?
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        encrypt_aes256_gcm! nonce sensitivity test failed:
                        - Got: Err(${err})
                        """
                    ))?

            # Test empty plaintext
            empty_plaintext = []
            when Crypto.encrypt_aes256_gcm!({ plaintext: empty_plaintext, key, nonce }) is
                Ok({ ciphertext: empty_ct, auth_tag: empty_tag }) ->
                    if List.len(empty_ct) == 0 && List.len(empty_tag) == 16 then
                        Stdout.line!("✓ Empty plaintext encrypts correctly")
                    else
                        Err(FailedExpectation(
                            """
                            encrypt_aes256_gcm! empty plaintext:
                            - Expected: ciphertext=0, auth_tag=16
                            - Got: ciphertext=${Inspect.to_str(List.len(empty_ct))}, auth_tag=${Inspect.to_str(List.len(empty_tag))}
                            """
                        ))
                Err(err) ->
                    Err(FailedExpectation(
                        """
                        encrypt_aes256_gcm! empty plaintext:
                        - Expected: Ok({ ciphertext, auth_tag })
                        - Got: Err(${err})
                        """
                    ))

        Err(err) ->
            Err(FailedExpectation(
                """
                encrypt_aes256_gcm! failed:
                - Expected: Ok({ ciphertext, auth_tag })
                - Got: Err(${err})
                """
            ))

test_aes_roundtrip! : {} => Result {} _
test_aes_roundtrip! = |{}|
    Stdout.line!("\nTesting AES-256-GCM encrypt/decrypt roundtrip:")?

    plaintext = Str.to_utf8("Hello, World! This is a test message.")
    key = Crypto.pbkdf2_hmac_sha256!({
        password: Str.to_utf8("my-secret-key"),
        salt: Str.to_utf8("authenticated encrypted cookie"),
        iterations: 1000,
        key_length: 32,
    })

    nonce = Crypto.random_bytes!(12) |> Result.map_err(|err| FailedExpectation("random_bytes! failed: ${err}"))?

    # Encrypt
    encrypt_result = Crypto.encrypt_aes256_gcm!({ plaintext, key, nonce }) |> Result.map_err(|err| FailedExpectation("encrypt_aes256_gcm! failed: ${err}"))?
    Stdout.line!("✓ Encrypted successfully")?

    # Decrypt
    decrypted = Crypto.decrypt_aes256_gcm!({
        ciphertext: encrypt_result.ciphertext,
        key,
        nonce,
        auth_tag: encrypt_result.auth_tag,
    }) |> Result.map_err(|err| FailedExpectation("decrypt_aes256_gcm! failed: ${err}"))?

    Stdout.line!("✓ Decrypted successfully")?

    # Verify roundtrip
    if decrypted == plaintext then
        Stdout.line!("✓ Roundtrip successful - decrypted matches original")
    else
        Err(FailedExpectation(
            """
            AES-256-GCM roundtrip:
            - Expected: ${Inspect.to_str(plaintext)}
            - Got: ${Inspect.to_str(decrypted)}
            """
        ))

test_aes_error_cases! : {} => Result {} _
test_aes_error_cases! = |{}|
    Stdout.line!("\nTesting AES-256-GCM error cases:")?

    plaintext = Str.to_utf8("test")
    valid_key = List.repeat(0x42, 32)
    valid_nonce = List.repeat(0x01, 12)

    # Test wrong key length
    wrong_key = List.repeat(0x42, 16)  # Too short
    result1 = Crypto.encrypt_aes256_gcm!({ plaintext, key: wrong_key, nonce: valid_nonce })

    when result1 is
        Err(_) ->
            Stdout.line!("✓ Correctly rejected wrong key length")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                encrypt_aes256_gcm! wrong key length:
                - Expected: Err(_)
                - Got: Ok(_)
                """
            ))?

    # Test wrong nonce length
    wrong_nonce = List.repeat(0x01, 8)  # Too short
    result2 = Crypto.encrypt_aes256_gcm!({ plaintext, key: valid_key, nonce: wrong_nonce })

    when result2 is
        Err(_) ->
            Stdout.line!("✓ Correctly rejected wrong nonce length")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                encrypt_aes256_gcm! wrong nonce length:
                - Expected: Err(_)
                - Got: Ok(_)
                """
            ))?

    # Test decryption with wrong auth tag
    valid_encrypt = Crypto.encrypt_aes256_gcm!({ plaintext, key: valid_key, nonce: valid_nonce }) |> Result.map_err(|err| FailedExpectation("encrypt_aes256_gcm! failed: ${err}"))?
    wrong_auth_tag = List.repeat(0xFF, 16)

    result3 = Crypto.decrypt_aes256_gcm!({
        ciphertext: valid_encrypt.ciphertext,
        key: valid_key,
        nonce: valid_nonce,
        auth_tag: wrong_auth_tag,
    })

    when result3 is
        Err(_) ->
            Stdout.line!("✓ Correctly rejected wrong auth tag")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                decrypt_aes256_gcm! wrong auth tag:
                - Expected: Err(_)
                - Got: Ok(_)
                """
            ))?

    # Test decrypt with wrong key length
    result4 = Crypto.decrypt_aes256_gcm!({
        ciphertext: valid_encrypt.ciphertext,
        key: wrong_key,  # 16 bytes instead of 32
        nonce: valid_nonce,
        auth_tag: valid_encrypt.auth_tag,
    })
    when result4 is
        Err(_) ->
            Stdout.line!("✓ Decrypt correctly rejected wrong key length")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                decrypt_aes256_gcm! wrong key length:
                - Expected: Err(_)
                - Got: Ok(_)
                """
            ))?

    # Test decrypt with wrong nonce length
    result5 = Crypto.decrypt_aes256_gcm!({
        ciphertext: valid_encrypt.ciphertext,
        key: valid_key,
        nonce: wrong_nonce,  # 8 bytes instead of 12
        auth_tag: valid_encrypt.auth_tag,
    })
    when result5 is
        Err(_) ->
            Stdout.line!("✓ Decrypt correctly rejected wrong nonce length")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                decrypt_aes256_gcm! wrong nonce length:
                - Expected: Err(_)
                - Got: Ok(_)
                """
            ))?

    # Test decrypt with wrong auth tag length
    wrong_auth_tag_len = List.repeat(0xFF, 8)  # 8 bytes instead of 16
    result6 = Crypto.decrypt_aes256_gcm!({
        ciphertext: valid_encrypt.ciphertext,
        key: valid_key,
        nonce: valid_nonce,
        auth_tag: wrong_auth_tag_len,
    })
    when result6 is
        Err(_) ->
            Stdout.line!("✓ Decrypt correctly rejected wrong auth tag length")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                decrypt_aes256_gcm! wrong auth tag length:
                - Expected: Err(_)
                - Got: Ok(_)
                """
            ))?

    # Test decrypt with wrong key (correct length) - main security property
    different_key = List.repeat(0x99, 32)  # Different 32-byte key
    result7 = Crypto.decrypt_aes256_gcm!({
        ciphertext: valid_encrypt.ciphertext,
        key: different_key,
        nonce: valid_nonce,
        auth_tag: valid_encrypt.auth_tag,
    })
    when result7 is
        Err(_) ->
            Stdout.line!("✓ Decrypt correctly rejected wrong key (correct length)")?
        Ok(_) ->
            Err(FailedExpectation(
                """
                decrypt_aes256_gcm! wrong key (correct length):
                - Expected: Err(_) - decryption should fail with wrong key
                - Got: Ok(_)
                """
            ))?

    # Test decrypt with tampered ciphertext - GCM should detect modification
    tampered_ciphertext = List.map(valid_encrypt.ciphertext, |byte| Num.bitwise_xor(byte, 0xFF))
    result8 = Crypto.decrypt_aes256_gcm!({
        ciphertext: tampered_ciphertext,
        key: valid_key,
        nonce: valid_nonce,
        auth_tag: valid_encrypt.auth_tag,
    })
    when result8 is
        Err(_) ->
            Stdout.line!("✓ Decrypt correctly detected tampered ciphertext")
        Ok(_) ->
            Err(FailedExpectation(
                """
                decrypt_aes256_gcm! tampered ciphertext:
                - Expected: Err(_) - GCM should detect modification
                - Got: Ok(_)
                """
            ))

expect_eq : Str, Str, Str -> Result {} [FailedExpectation Str]
expect_eq = |label, expected, actual|
    if expected != actual then
        Err(FailedExpectation(
            """
            ${label}:
            - Expected: ${expected}
            - Got: ${actual}
            """
        ))
    else
        Ok({})

test_hash! : {} => Result {} _
test_hash! = |{}|
    Stdout.line!("\nTesting Crypto.hash!:")?

    # SHA-1 of empty string (RFC 3174)
    expect_eq(
        "hash! SHA-1 of empty",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        Crypto.hash!([], Sha1),
    )?
    Stdout.line!("✓ SHA-1 of empty input matches RFC 3174")?

    # SHA-1 of "abc" (RFC 3174 test vector)
    expect_eq(
        "hash! SHA-1 of \"abc\"",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        Crypto.hash!(Str.to_utf8("abc"), Sha1),
    )?
    Stdout.line!("✓ SHA-1 of \"abc\" matches RFC 3174")?

    # SHA-1 of pangram (commonly cited test vector)
    expect_eq(
        "hash! SHA-1 of pangram",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        Crypto.hash!(Str.to_utf8("The quick brown fox jumps over the lazy dog"), Sha1),
    )?
    Stdout.line!("✓ SHA-1 of pangram matches known value")?

    # SHA-256 of empty string (NIST)
    expect_eq(
        "hash! SHA-256 of empty",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        Crypto.hash!([], Sha256),
    )?
    Stdout.line!("✓ SHA-256 of empty input matches NIST")?

    # SHA-256 of "abc" (NIST test vector)
    expect_eq(
        "hash! SHA-256 of \"abc\"",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Crypto.hash!(Str.to_utf8("abc"), Sha256),
    )?
    Stdout.line!("✓ SHA-256 of \"abc\" matches NIST")?

    # SHA-512 of empty string (NIST)
    expect_eq(
        "hash! SHA-512 of empty",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        Crypto.hash!([], Sha512),
    )?
    Stdout.line!("✓ SHA-512 of empty input matches NIST")?

    # SHA-384 of "abc" (NIST test vector)
    expect_eq(
        "hash! SHA-384 of \"abc\"",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        Crypto.hash!(Str.to_utf8("abc"), Sha384),
    )?
    Stdout.line!("✓ SHA-384 of \"abc\" matches NIST")?

    # Multi-byte UTF-8: "héllo wörld" — sanity check that Str→bytes→hash
    # is wired correctly end-to-end. The UTF-8 encoding of this string is
    # 13 bytes (not 11), so any byte/char confusion would give a different hash.
    # Reference values computed independently via openssl.
    utf8_bytes = Str.to_utf8("héllo wörld")
    expect_eq(
        "hash! SHA-1 of UTF-8 \"héllo wörld\"",
        "24e9f5c07847ff8a2a9fa77456655792f5bc7f9f",
        Crypto.hash!(utf8_bytes, Sha1),
    )?
    expect_eq(
        "hash! SHA-256 of UTF-8 \"héllo wörld\"",
        "a1003f7d04a4115711d0b48a2eaf1359ce565d2d2a6fd65098dfcffadeeef59f",
        Crypto.hash!(utf8_bytes, Sha256),
    )?
    Stdout.line!("✓ Multi-byte UTF-8 hashes correctly (SHA-1 + SHA-256)")?

    # Determinism: same input → same output
    a = Crypto.hash!(Str.to_utf8("hello world"), Sha1)
    b = Crypto.hash!(Str.to_utf8("hello world"), Sha1)
    if a != b then
        Err(FailedExpectation("hash! not deterministic"))?
    else
        {}
    Stdout.line!("✓ Deterministic")

test_hash_file! : {} => Result {} _
test_hash_file! = |{}|
    Stdout.line!("\nTesting Crypto.hash_file!:")?

    # Idempotency: ensure no leftover temp files from a prior failed run.
    test_path = "tests/test_hash_file.tmp"
    empty_path = "tests/test_hash_empty.tmp"
    File.delete!(test_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})

    # Write a known file and hash it with all 4 algorithms.
    File.write_bytes!(Str.to_utf8("abc"), test_path)
        |> Result.map_err(|e| FailedExpectation("Could not write test file: ${Inspect.to_str(e)}"))?

    sha1 = Crypto.hash_file!(test_path, Sha1)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-1 failed: ${e}"))?
    expect_eq("hash_file! SHA-1 of \"abc\"", "a9993e364706816aba3e25717850c26c9cd0d89d", sha1)?
    Stdout.line!("✓ SHA-1 of file containing \"abc\" matches RFC 3174")?

    sha256 = Crypto.hash_file!(test_path, Sha256)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-256 failed: ${e}"))?
    expect_eq("hash_file! SHA-256 of \"abc\"", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha256)?
    Stdout.line!("✓ SHA-256 of file matches NIST")?

    sha384 = Crypto.hash_file!(test_path, Sha384)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-384 failed: ${e}"))?
    expect_eq("hash_file! SHA-384 of \"abc\"", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", sha384)?
    Stdout.line!("✓ SHA-384 of file matches NIST")?

    sha512 = Crypto.hash_file!(test_path, Sha512)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-512 failed: ${e}"))?
    expect_eq("hash_file! SHA-512 of \"abc\"", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", sha512)?
    Stdout.line!("✓ SHA-512 of file matches NIST")?

    # Cross-check: hash!(bytes) and hash_file!(file with same bytes) must agree
    # for every algorithm. This catches a class of bugs where one path is broken
    # but happens to match a hardcoded test vector that's also wrong.
    abc_bytes = Str.to_utf8("abc")
    expect_eq("cross-check SHA-1", Crypto.hash!(abc_bytes, Sha1), sha1)?
    expect_eq("cross-check SHA-256", Crypto.hash!(abc_bytes, Sha256), sha256)?
    expect_eq("cross-check SHA-384", Crypto.hash!(abc_bytes, Sha384), sha384)?
    expect_eq("cross-check SHA-512", Crypto.hash!(abc_bytes, Sha512), sha512)?
    Stdout.line!("✓ hash! and hash_file! agree for all 4 algorithms")?

    # Empty file
    File.write_bytes!([], empty_path)
        |> Result.map_err(|e| FailedExpectation("Could not write empty file: ${Inspect.to_str(e)}"))?
    sha1_empty = Crypto.hash_file!(empty_path, Sha1)
        |> Result.map_err(|e| FailedExpectation("hash_file! empty failed: ${e}"))?
    expect_eq("hash_file! SHA-1 of empty", "da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1_empty)?
    Stdout.line!("✓ SHA-1 of empty file matches RFC 3174")?

    # Missing file → error. The directory itself doesn't exist either, so this
    # path is guaranteed-absent regardless of any leftover state.
    when Crypto.hash_file!("tests/nonexistent_dir/missing.tmp", Sha1) is
        Err(_) -> Stdout.line!("✓ Missing file returns Err")?
        Ok(_) -> Err(FailedExpectation("hash_file! should fail on missing file"))?

    # Cleanup
    File.delete!(test_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})

    Ok({})

test_hash_file_chunks! : {} => Result {} _
test_hash_file_chunks! = |{}|
    Stdout.line!("\nTesting Crypto.hash_file_chunks!:")?

    # Idempotency: ensure no leftover temp files from a prior failed run.
    abc_path = "tests/test_hash_chunks_abc.tmp"
    empty_path = "tests/test_hash_chunks_empty.tmp"
    boundary_path = "tests/test_hash_chunks_boundary.tmp"
    over_path = "tests/test_hash_chunks_over.tmp"
    big_path = "tests/test_hash_chunks_big.tmp"
    File.delete!(abc_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})
    File.delete!(boundary_path) |> Result.with_default({})
    File.delete!(over_path) |> Result.with_default({})
    File.delete!(big_path) |> Result.with_default({})

    # ── SHA-1 reference: "abc" with 1-byte chunks ───────────────────────────
    # Algorithm: SHA1 each chunk, concatenate raw 20-byte digests, SHA1 the result.
    #
    # SHA1("a") = 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8 (raw bytes B0)
    # SHA1("b") = e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98 (raw bytes B1)
    # SHA1("c") = 84a516841ba77a5b4648de2cd0dfcb30ea46dbb4 (raw bytes B2)
    # SHA1(B0 ++ B1 ++ B2) = 24ba5eeff007db49a25c68779c503992561ab37f
    # Computed independently via openssl.
    File.write_bytes!(Str.to_utf8("abc"), abc_path)
        |> Result.map_err(|e| FailedExpectation("Could not write file: ${Inspect.to_str(e)}"))?

    chunks_1byte = Crypto.hash_file_chunks!(abc_path, { algorithm: Sha1, chunk_size_bytes: 1 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! failed: ${e}"))?
    expect_eq("hash_file_chunks! \"abc\" SHA-1 chunk=1", "24ba5eeff007db49a25c68779c503992561ab37f", chunks_1byte)?
    Stdout.line!("✓ SHA-1 chunked hash of \"abc\" with 1-byte chunks matches reference")?

    # Single-chunk case: chunk_size larger than file → one chunk
    # SHA1(SHA1("abc")) = 0d3ced9bec10a777aec23ccc353a8c08a633045e
    chunks_big = Crypto.hash_file_chunks!(abc_path, { algorithm: Sha1, chunk_size_bytes: 1000 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! big chunk failed: ${e}"))?
    expect_eq("hash_file_chunks! \"abc\" SHA-1 chunk=1000", "0d3ced9bec10a777aec23ccc353a8c08a633045e", chunks_big)?
    Stdout.line!("✓ Single-chunk case (chunk_size > file_size) works")?

    # ── chunk_size_bytes = 0 → clamped to 1 (matches joy frontend) ──────────
    # Should produce identical output to chunk_size_bytes = 1.
    chunks_zero = Crypto.hash_file_chunks!(abc_path, { algorithm: Sha1, chunk_size_bytes: 0 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! chunk_size=0 failed: ${e}"))?
    expect_eq(
        "hash_file_chunks! chunk_size=0 must equal chunk_size=1 (clamped)",
        chunks_1byte,
        chunks_zero,
    )?
    Stdout.line!("✓ chunk_size_bytes=0 is clamped to 1 (matches joy)")?

    # ── SHA-256 reference: "abcdef" with 3-byte chunks (2 chunks: "abc","def") ─
    # Computed independently via openssl:
    #   SHA256("abc") || SHA256("def") → SHA256(.) =
    #   9c04d30057b754af1b2d2d4f5675782dd61a5a659c34ee6c2af47526b66cafa6
    File.write_bytes!(Str.to_utf8("abcdef"), boundary_path)
        |> Result.map_err(|e| FailedExpectation("Could not write boundary file: ${Inspect.to_str(e)}"))?

    chunks_sha256 = Crypto.hash_file_chunks!(boundary_path, { algorithm: Sha256, chunk_size_bytes: 3 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! SHA-256 failed: ${e}"))?
    expect_eq(
        "hash_file_chunks! \"abcdef\" SHA-256 chunk=3",
        "9c04d30057b754af1b2d2d4f5675782dd61a5a659c34ee6c2af47526b66cafa6",
        chunks_sha256,
    )?
    Stdout.line!("✓ SHA-256 chunked hash works (verifies algorithm dispatch in chunk path)")?

    # Empty file: zero chunks → SHA1 of empty bytes
    File.write_bytes!([], empty_path)
        |> Result.map_err(|e| FailedExpectation("Could not write empty file: ${Inspect.to_str(e)}"))?
    chunks_empty = Crypto.hash_file_chunks!(empty_path, { algorithm: Sha1, chunk_size_bytes: 16 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! empty failed: ${e}"))?
    expect_eq("hash_file_chunks! empty file SHA-1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", chunks_empty)?
    Stdout.line!("✓ Empty file → SHA-1 of empty input")?

    # Exact chunk boundary: 6-byte file with 3-byte chunks → 2 chunks ("abc","def")
    # Reference: 18a55436ce198b1412df9fa91896524ce4173053
    chunks_boundary = Crypto.hash_file_chunks!(boundary_path, { algorithm: Sha1, chunk_size_bytes: 3 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! boundary failed: ${e}"))?
    expect_eq("hash_file_chunks! exact boundary 6/3", "18a55436ce198b1412df9fa91896524ce4173053", chunks_boundary)?
    Stdout.line!("✓ Exact chunk boundary works (6 bytes / 3-byte chunks)")?

    # Boundary + 1: 7-byte file with 3-byte chunks → 2 full + 1 partial ("abc","def","g")
    # Reference: e05707a95333c72b31bb66e6a8bed63dd254649a
    File.write_bytes!(Str.to_utf8("abcdefg"), over_path)
        |> Result.map_err(|e| FailedExpectation("Could not write over file: ${Inspect.to_str(e)}"))?

    chunks_over = Crypto.hash_file_chunks!(over_path, { algorithm: Sha1, chunk_size_bytes: 3 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! over failed: ${e}"))?
    expect_eq("hash_file_chunks! partial last chunk 7/3", "e05707a95333c72b31bb66e6a8bed63dd254649a", chunks_over)?
    Stdout.line!("✓ Partial last chunk works (7 bytes / 3-byte chunks)")?

    # ── Streaming test: 100 distinct 1024-byte blocks ──────────────────────
    # Exercises the read loop 100 times with VARIED data so each chunk is
    # distinguishable. Block i (0-indexed) is 1024 copies of byte (i+1), so
    # chunk 0 hashes differently from chunk 1, etc.
    #
    # This catches bugs that uniform data (zeros) would miss:
    # - Offset tracking bugs (always reading from offset 0): chunks would all
    #   be identical to chunk 0, producing a different final hash.
    # - Buffer-reuse bugs: stale bytes from a previous chunk would corrupt the
    #   current chunk's hash.
    # - Chunk reordering or duplication: any swap changes the result because
    #   chunks are distinguishable.
    #
    # Reference computed independently via openssl on the same byte sequence:
    #   awk 'BEGIN { for (i=1; i<=100; i++) for (j=0; j<1024; j++) printf "%c", i }' > varied.bin
    #   for c in $(seq 0 99); do
    #     dd if=varied.bin bs=1024 count=1 skip=$c status=none | openssl dgst -sha1 -binary
    #   done > concat.bin
    #   openssl dgst -sha1 concat.bin
    # → 324c11a8fb079d649d66774a73a965a2cc30405d
    big_data =
        List.range({ start: At(1u8), end: At(100u8) })
        |> List.map(|n| List.repeat(n, 1024))
        |> List.join
    File.write_bytes!(big_data, big_path)
        |> Result.map_err(|e| FailedExpectation("Could not write big file: ${Inspect.to_str(e)}"))?

    chunks_streaming = Crypto.hash_file_chunks!(big_path, { algorithm: Sha1, chunk_size_bytes: 1024 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! streaming failed: ${e}"))?
    expect_eq(
        "hash_file_chunks! 100 distinct 1024-byte blocks SHA-1 chunk=1024",
        "324c11a8fb079d649d66774a73a965a2cc30405d",
        chunks_streaming,
    )?
    Stdout.line!("✓ 100 distinct chunks streaming hash matches reference")?

    # Missing file → error. Use a path under a non-existent directory so
    # nothing can leave a stale file at this location.
    when Crypto.hash_file_chunks!("tests/nonexistent_dir/missing.tmp", { algorithm: Sha1, chunk_size_bytes: 16 }) is
        Err(_) -> Stdout.line!("✓ Missing file returns Err")?
        Ok(_) -> Err(FailedExpectation("hash_file_chunks! should fail on missing file"))?

    # Cleanup
    File.delete!(abc_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})
    File.delete!(boundary_path) |> Result.with_default({})
    File.delete!(over_path) |> Result.with_default({})
    File.delete!(big_path) |> Result.with_default({})

    Ok({})
