"""T5 — expired, not-yet-valid, wrong-audience, wrong-issuer and incomplete tokens are rejected."""

import time

import pytest

from authorityguard.capabilities.keys import REQUIRED_CLAIMS, TokenInvalid
from tests.unit.test_token_signature import _claims


def _code(signer, claims, audience=None):
    with pytest.raises(TokenInvalid) as exc:
        signer.verify(signer.sign(claims), audience=audience)
    return exc.value.code


def test_expired_token_rejected(signer):
    past = int(time.time()) - 3600
    assert _code(signer, _claims(iat=past, nbf=past, exp=past + 60)) == "expired"


def test_not_yet_valid_token_rejected(signer):
    future = int(time.time()) + 3600
    assert _code(signer, _claims(nbf=future, exp=future + 60)) == "not_yet_valid"


def test_wrong_audience_rejected(signer):
    assert _code(signer, _claims(aud="some-other-service")) == "wrong_audience"


def test_verifier_for_other_audience_rejects_our_token(signer):
    assert _code(signer, _claims(), audience="billing-service") == "wrong_audience"


def test_wrong_issuer_rejected(signer):
    assert _code(signer, _claims(iss="evil-issuer")) == "wrong_issuer"


@pytest.mark.parametrize("claim", REQUIRED_CLAIMS)
def test_missing_required_claim_rejected(signer, claim):
    claims = _claims()
    del claims[claim]
    # A token without `aud` fails the audience check before the "required" check.
    assert _code(signer, claims) in {"missing_claim", "wrong_audience"}
