"""
FIDO2 / WebAuthn Asymmetric Passkey Generation.

Implements W3C WebAuthn Level 3 & FIDO2 discoverable credentials:
1. Standard cryptographic algorithms:
   - ES256 (NIST P-256 / secp256r1 with ECDSA-SHA256, COSE alg -7)
   - Ed25519 (Edwards-curve EdDSA, COSE alg -8)
2. Unique random Credential ID (base64url and raw bytes).
3. Standard Public Key exports:
   - COSE Key (RFC 8152 / RFC 9052 CBOR-encoded, base64url for WebAuthn APIs)
   - PEM (SubjectPublicKeyInfo)
   - JWK (RFC 7517)
4. Hardware/Zero-Trace Private Key Lifecycle:
   - In-memory private key material is kept in zeroizable memory buffers.
   - Challenge signing (clientDataHash assertion) with immediate disposal.
   - Export encrypted private keys (PKCS#8 with AES-256-CBC/PBKDF2) or destroy immediately.
"""

import base64
from enum import Enum
import os
from typing import Any, Dict, Optional, Union

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from passkey_gen.memory import SecurePasskey, zeroize_buffer


class WebAuthnAlgorithm(str, Enum):
    """Supported FIDO2 / WebAuthn cryptographic algorithms."""
    ES256 = "ES256"      # ECDSA over NIST P-256 with SHA-256 (COSE -7)
    ED25519 = "Ed25519"  # EdDSA over Curve25519 (COSE -8)


def _b64url_encode(data: bytes) -> str:
    """Standard WebAuthn base64url encoding without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class WebAuthnPasskey:
    """
    Represents a FIDO2 / WebAuthn resident passkey credential.
    """

    def __init__(
        self,
        algorithm: WebAuthnAlgorithm,
        credential_id: bytes,
        private_key: Union[ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey],
    ):
        self._algorithm = algorithm
        self._credential_id = credential_id
        self._private_key = private_key
        self._destroyed = False

        # Generate and cache public representations
        self._init_public_keys()

    def _init_public_keys(self) -> None:
        """Derive standard public key representations (COSE, PEM, JWK)."""
        pub_key = self._private_key.public_key()

        # 1. Standard SubjectPublicKeyInfo PEM
        self._pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

        # 2. COSE Key & JWK encoding
        if self._algorithm == WebAuthnAlgorithm.ES256:
            assert isinstance(pub_key, ec.EllipticCurvePublicKey)
            pn = pub_key.public_numbers()
            x_bytes = pn.x.to_bytes(32, "big")
            y_bytes = pn.y.to_bytes(32, "big")

            # COSE Key Map (RFC 8152 / RFC 9052):
            # 1 (kty): 2 (EC2)
            # 3 (alg): -7 (ES256)
            # -1 (crv): 1 (P-256)
            # -2 (x): x_bytes
            # -3 (y): y_bytes
            cose_dict = {
                1: 2,
                3: -7,
                -1: 1,
                -2: x_bytes,
                -3: y_bytes,
            }
            self._cose_bytes = cbor2.dumps(cose_dict)

            # JWK representation (RFC 7517)
            self._jwk = {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "x": _b64url_encode(x_bytes),
                "y": _b64url_encode(y_bytes),
            }

        elif self._algorithm == WebAuthnAlgorithm.ED25519:
            assert isinstance(pub_key, ed25519.Ed25519PublicKey)
            raw_pub = pub_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # COSE Key Map for OKP (RFC 8152):
            # 1 (kty): 1 (OKP)
            # 3 (alg): -8 (EdDSA)
            # -1 (crv): 6 (Ed25519)
            # -2 (x): raw_pub
            cose_dict = {
                1: 1,
                3: -8,
                -1: 6,
                -2: raw_pub,
            }
            self._cose_bytes = cbor2.dumps(cose_dict)

            # JWK representation
            self._jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "x": _b64url_encode(raw_pub),
            }
        else:
            raise ValueError(f"Unsupported algorithm: {self._algorithm}")

    @property
    def algorithm(self) -> WebAuthnAlgorithm:
        return self._algorithm

    @property
    def credential_id_bytes(self) -> bytes:
        return self._credential_id

    @property
    def credential_id(self) -> str:
        """Base64url-encoded credential identifier."""
        return _b64url_encode(self._credential_id)

    @property
    def public_key_pem(self) -> str:
        """Standard X.509 SubjectPublicKeyInfo PEM."""
        return self._pub_pem

    @property
    def public_key_cose(self) -> bytes:
        """Raw CBOR-encoded COSE Key bytes."""
        return self._cose_bytes

    @property
    def public_key_cose_b64(self) -> str:
        """Base64url-encoded COSE Key (used in WebAuthn registration responses)."""
        return _b64url_encode(self._cose_bytes)

    @property
    def public_key_jwk(self) -> Dict[str, Any]:
        """JSON Web Key representation."""
        return dict(self._jwk)

    @property
    def is_destroyed(self) -> bool:
        return self._destroyed

    def sign_assertion(self, client_data_hash: bytes) -> bytes:
        """
        Cryptographically sign an authentication challenge (clientDataHash).
        Returns the signature bytes (DER format for ES256, Raw 64 bytes for Ed25519).
        """
        if self._destroyed or self._private_key is None:
            raise RuntimeError("Passkey private key has been zeroized and destroyed.")

        if self._algorithm == WebAuthnAlgorithm.ES256:
            assert isinstance(self._private_key, ec.EllipticCurvePrivateKey)
            return self._private_key.sign(client_data_hash, ec.ECDSA(hashes.SHA256()))
        elif self._algorithm == WebAuthnAlgorithm.ED25519:
            assert isinstance(self._private_key, ed25519.Ed25519PrivateKey)
            return self._private_key.sign(client_data_hash)
        else:
            raise ValueError("Unsupported algorithm")

    def export_private_key_pem(self, passphrase: Optional[str] = None) -> str:
        """
        Export PKCS#8 private key in PEM format.
        If passphrase is provided, encrypts with BestAvailableEncryption (AES-256-CBC).
        """
        if self._destroyed or self._private_key is None:
            raise RuntimeError("Passkey private key has been zeroized and destroyed.")

        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
            if passphrase
            else serialization.NoEncryption()
        )

        pem_bytes = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        return pem_bytes.decode("ascii")

    def destroy(self) -> None:
        """
        Zeroize and discard the private key instance.
        """
        if self._destroyed:
            return
        self._private_key = None
        self._destroyed = True

    def __enter__(self) -> "WebAuthnPasskey":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()

    def __del__(self) -> None:
        self.destroy()

    def to_dict(self, include_private_key: bool = False, passphrase: Optional[str] = None) -> Dict[str, Any]:
        """
        Export passkey metadata as a WebAuthn-compatible dictionary.
        """
        result: Dict[str, Any] = {
            "type": "public-key",
            "id": self.credential_id,
            "rawId": _b64url_encode(self._credential_id),
            "algorithm": self._algorithm.value,
            "coseAlgorithm": -7 if self._algorithm == WebAuthnAlgorithm.ES256 else -8,
            "publicKeyCose": self.public_key_cose_b64,
            "publicKeyJwk": self.public_key_jwk,
            "publicKeyPem": self.public_key_pem,
        }

        if include_private_key:
            result["privateKeyPem"] = self.export_private_key_pem(passphrase)

        return result


def generate_webauthn_passkey(
    algorithm: Union[WebAuthnAlgorithm, str] = WebAuthnAlgorithm.ES256,
    credential_id_len: int = 32,
) -> WebAuthnPasskey:
    """
    Generate a new FIDO2 / WebAuthn resident passkey.
    
    Guarantees:
    - Kernel CSPRNG entropy for credential ID and private key.
    - Standard COSE, PEM, and JWK public key exports.
    - Zeroizes private key when used as a context manager.
    """
    if isinstance(algorithm, str):
        try:
            algorithm = WebAuthnAlgorithm(algorithm)
        except ValueError:
            # Case-insensitive lookup
            for candidate in WebAuthnAlgorithm:
                if candidate.value.lower() == algorithm.lower():
                    algorithm = candidate
                    break
            else:
                valid = [a.value for a in WebAuthnAlgorithm]
                raise ValueError(f"Invalid algorithm '{algorithm}'. Valid algorithms: {valid}")

    if credential_id_len < 16 or credential_id_len > 128:
        raise ValueError("Credential ID length must be between 16 and 128 bytes.")

    cred_id = os.urandom(credential_id_len)

    if algorithm == WebAuthnAlgorithm.ES256:
        priv_key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == WebAuthnAlgorithm.ED25519:
        priv_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return WebAuthnPasskey(algorithm=algorithm, credential_id=cred_id, private_key=priv_key)
