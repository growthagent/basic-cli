app [main!] { pf: platform "../platform/main.roc" }

import pf.Stdout
import pf.Crypto
import pf.Arg exposing [Arg]

# Tests Crypto module functions: random_bytes, bcrypt, AES-256-GCM, and PBKDF2

main! : List Arg => Result {} _
main! = |_args|
    Stdout.line!("Testing Crypto module functions...")?

    test_random_bytes!({})?
    test_pbkdf2!({})?
    test_bcrypt!({})?
    test_aes_encryption!({})?
    test_aes_roundtrip!({})?
    test_aes_error_cases!({})?

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

        Ok(hash) ->
            hash_str = Str.from_utf8(hash) |> Result.with_default("<invalid utf8>")

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
                Ok(hash2) ->
                    hash2_str = Str.from_utf8(hash2) |> Result.with_default("<invalid utf8>")
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
                Ok(empty_hash) ->
                    empty_hash_str = Str.from_utf8(empty_hash) |> Result.with_default("<invalid utf8>")
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
