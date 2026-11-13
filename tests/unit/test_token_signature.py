"""T4 — forged or tampered tokens must be rejected by the signature check."""

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authorityguard.capabilities.keys import Signer, TokenInvalid


def _claims(**overrides):
    now = int(time.time())
    base = {
        "iss": "authorityguard",
        "aud": "authorityguard-gateway",
        "sub": "agent-1",
        "jti": "cap-1",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "scopes": [{"action": "file.read", "resource": "/demo/*"}],
    }
    return base | overrides


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def test_valid_token_round_trips(signer):
    claims = signer.verify(signer.sign(_claims()))
    assert claims["sub"] == "agent-1"


def test_token_carries_key_id(signer):
    assert jwt.get_unverified_header(signer.sign(_claims()))["kid"] == signer.key_id


def test_tampered_payload_rejected(signer):
    # Attacker edits the scopes to add email.send but cannot re-sign.
    header, _payload, sig = signer.sign(_claims()).split(".")
    evil = _claims(scopes=[{"action": "email.send", "resource": "*"}])
    with pytest.raises(TokenInvalid) as exc:
        signer.verify(f"{header}.{_b64(evil)}.{sig}")
    assert exc.value.code == "invalid_signature"


def test_token_signed_by_another_key_rejected(signer):
    attacker = Signer(Ed25519PrivateKey.generate(), signer.issuer, signer.audience)
    with pytest.raises(TokenInvalid) as exc:
        signer.verify(attacker.sign(_claims()))
    assert exc.value.code == "invalid_signature"


def test_alg_none_rejected(signer):
    unsigned = jwt.encode(_claims(), key=None, algorithm="none")
    with pytest.raises(TokenInvalid) as exc:
        signer.verify(unsigned)
    assert exc.value.code in {"invalid_algorithm", "malformed"}


def test_hs256_with_public_key_confusion_rejected(signer):
    # Classic attack: sign with HMAC using the *public* key as the shared secret.
    public_pem = signer.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64(_claims())
    import hashlib
    import hmac

    sig = hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    forged = f"{header}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    with pytest.raises(TokenInvalid) as exc:
        signer.verify(forged)
    assert exc.value.code == "invalid_algorithm"


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "x" * 200])
def test_garbage_rejected(signer, garbage):
    with pytest.raises(TokenInvalid) as exc:
        signer.verify(garbage)
    assert exc.value.code == "malformed"
