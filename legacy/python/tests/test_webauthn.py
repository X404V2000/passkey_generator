import base64
import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from passkey_gen.webauthn import (
    WebAuthnAlgorithm,
    WebAuthnPasskey,
    generate_webauthn_passkey,
)


def test_generate_es256_passkey():
    with generate_webauthn_passkey(WebAuthnAlgorithm.ES256) as passkey:
        assert passkey.algorithm == WebAuthnAlgorithm.ES256
        assert len(passkey.credential_id_bytes) == 32
        assert len(passkey.credential_id) > 0
        assert "BEGIN PUBLIC KEY" in passkey.public_key_pem

        # Verify COSE CBOR format
        cose = cbor2.loads(passkey.public_key_cose)
        assert cose[1] == 2  # EC2
        assert cose[3] == -7  # ES256
        assert cose[-1] == 1  # P-256
        assert len(cose[-2]) == 32  # x
        assert len(cose[-3]) == 32  # y

        # Verify JWK
        jwk = passkey.public_key_jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["alg"] == "ES256"


def test_generate_ed25519_passkey():
    with generate_webauthn_passkey(WebAuthnAlgorithm.ED25519) as passkey:
        assert passkey.algorithm == WebAuthnAlgorithm.ED25519
        assert len(passkey.credential_id_bytes) == 32
        assert "BEGIN PUBLIC KEY" in passkey.public_key_pem

        # Verify COSE CBOR format
        cose = cbor2.loads(passkey.public_key_cose)
        assert cose[1] == 1  # OKP
        assert cose[3] == -8  # EdDSA
        assert cose[-1] == 6  # Ed25519
        assert len(cose[-2]) == 32  # raw pub

        # Verify JWK
        jwk = passkey.public_key_jwk
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["alg"] == "EdDSA"


def test_es256_sign_and_verify_assertion():
    challenge = b"webauthn_auth_challenge_hash_32b"  # 32-byte test challenge
    with generate_webauthn_passkey(WebAuthnAlgorithm.ES256) as passkey:
        sig = passkey.sign_assertion(challenge)
        assert len(sig) > 0

        # Cryptographically verify signature using public key
        cose = cbor2.loads(passkey.public_key_cose)
        x = int.from_bytes(cose[-2], "big")
        y = int.from_bytes(cose[-3], "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        pub_key = pub_numbers.public_key()

        # Should not raise exception
        pub_key.verify(sig, challenge, ec.ECDSA(hashes.SHA256()))


def test_ed25519_sign_and_verify_assertion():
    challenge = b"webauthn_ed25519_challenge_hash!"
    with generate_webauthn_passkey(WebAuthnAlgorithm.ED25519) as passkey:
        sig = passkey.sign_assertion(challenge)
        assert len(sig) == 64

        # Cryptographically verify signature
        cose = cbor2.loads(passkey.public_key_cose)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])

        # Should not raise exception
        pub_key.verify(sig, challenge)


def test_private_key_export_unencrypted_and_encrypted():
    with generate_webauthn_passkey(WebAuthnAlgorithm.ES256) as passkey:
        pem_plain = passkey.export_private_key_pem()
        assert "BEGIN PRIVATE KEY" in pem_plain

        pem_encrypted = passkey.export_private_key_pem(passphrase="SecretPass123!")
        assert "BEGIN ENCRYPTED PRIVATE KEY" in pem_encrypted


def test_webauthn_destruction_lifecycle():
    passkey = generate_webauthn_passkey(WebAuthnAlgorithm.ES256)
    assert not passkey.is_destroyed
    passkey.destroy()
    assert passkey.is_destroyed

    with pytest.raises(RuntimeError, match="zeroized and destroyed"):
        passkey.sign_assertion(b"test")

    with pytest.raises(RuntimeError, match="zeroized and destroyed"):
        passkey.export_private_key_pem()


def test_webauthn_invalid_options():
    with pytest.raises(ValueError, match="Invalid algorithm"):
        generate_webauthn_passkey("RSA-INVALID")

    with pytest.raises(ValueError, match="Credential ID length"):
        generate_webauthn_passkey(WebAuthnAlgorithm.ES256, credential_id_len=4)
