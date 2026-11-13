"""Signing and verifying capability tokens.

Uses PyJWT with Ed25519 (alg "EdDSA"). Verification accepts *only* EdDSA, which blocks the
classic "alg: none" and HS256-with-public-key confusion attacks (threat T4). No custom crypto."""

import hashlib
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from authorityguard.config import get_settings

log = logging.getLogger(__name__)

ALGORITHM = "EdDSA"
REQUIRED_CLAIMS = ["iss", "aud", "sub", "jti", "iat", "nbf", "exp"]


class TokenInvalid(Exception):
    """Token failed verification. `code` is a stable, machine-readable reason."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Signer:
    private_key: Ed25519PrivateKey
    issuer: str
    audience: str

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def key_id(self) -> str:
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw).hexdigest()[:16]

    def sign(self, claims: dict[str, Any]) -> str:
        headers = {"kid": self.key_id}
        return jwt.encode(claims, self.private_key, algorithm=ALGORITHM, headers=headers)

    def verify(self, token: str, audience: str | None = None) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                self.public_key,
                algorithms=[ALGORITHM],
                audience=audience or self.audience,
                issuer=self.issuer,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenInvalid("expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise TokenInvalid("not_yet_valid") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenInvalid("wrong_audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenInvalid("wrong_issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise TokenInvalid("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise TokenInvalid("invalid_signature") from exc
        except jwt.InvalidAlgorithmError as exc:
            raise TokenInvalid("invalid_algorithm") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenInvalid("malformed") from exc


def token_hash(token: str) -> str:
    """Stored instead of the token itself, so a database leak does not leak usable tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


def load_or_create_private_key(path: Path, allow_create: bool) -> Ed25519PrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError(f"{path} is not an Ed25519 private key")
        return key
    if not allow_create:
        raise RuntimeError(f"Signing key not found at {path}; set AG_SIGNING_KEY_PATH")

    log.warning("Generating a new development signing key at %s", path)
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return key


@lru_cache
def get_signer() -> Signer:
    s = get_settings()
    key = load_or_create_private_key(Path(s.signing_key_path), allow_create=s.env == "dev")
    return Signer(private_key=key, issuer=s.token_issuer, audience=s.token_audience)
