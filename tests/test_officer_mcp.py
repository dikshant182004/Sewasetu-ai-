"""Officer MCP token, block authorization and decision-guard tests.

These tests do not claim to exercise a live PostgreSQL case workflow; see
docs/OFFICER-MCP.md for the required deployment-level verification.
"""
import json
import os
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "app"))
os.environ.setdefault("SECRET_KEY", "test-only")
import _stubs  # noqa: F401,E402
import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

import officer_mcp  # noqa: E402


class OfficerTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private.public_key()))
        jwk.update({"kid": "officer-test-key", "alg": "RS256", "use": "sig"})
        cls.jwks = {"keys": [jwk]}
        cls.original_jwks = officer_mcp._jwks
        officer_mcp._jwks = lambda: cls.jwks

    @classmethod
    def tearDownClass(cls):
        officer_mcp._jwks = cls.original_jwks
        officer_mcp._jwks_cache = None

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": officer_mcp.ISSUER,
            "aud": officer_mcp.AUDIENCE,
            "sub": "officer:admin",
            "role": "officer",
            "scope": "officer",
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private, algorithm="RS256",
                          headers={"kid": "officer-test-key"})

    def test_rfc9728_metadata_is_path_specific(self):
        self.assertEqual(officer_mcp.RESOURCE_METADATA_PATH,
                         "/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(officer_mcp.RESOURCE_METADATA_URL,
                         "http://localhost:8200/.well-known/oauth-protected-resource/mcp")

    def test_valid_assigned_officer_is_accepted(self):
        claims = officer_mcp.verify_bearer("Bearer " + self.token())
        self.assertEqual(claims["sub"], "officer:admin")
        self.assertEqual(officer_mcp.officer_blocks("admin"), ("Sonari",))

    def test_citizen_token_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(
                sub="citizen:9000000001", role="citizen", scope="citizen"))

    def test_wrong_audience_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(aud="http://other.example/mcp"))

    def test_wrong_issuer_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(iss="https://attacker.example"))

    def test_wrong_scope_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(scope="openid profile"))

    def test_unassigned_officer_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(sub="officer:unassigned"))

    def test_malformed_subject_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(sub="officer:../admin"))

    def test_expired_token_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer("Bearer " + self.token(
                exp=int(time.time()) - 60, iat=int(time.time()) - 120))

    def test_missing_bearer_is_rejected(self):
        with self.assertRaises(officer_mcp.AuthError):
            officer_mcp.verify_bearer(None)

    def test_decision_needs_explicit_confirmation(self):
        result = officer_mcp.record_case_decision(
            "SSP26000001", "APPROVED", "Documents verified", False)
        self.assertFalse(result["recorded"])
        self.assertEqual(result["error"], "officer_confirmation_required")

    def test_decision_reason_is_required(self):
        result = officer_mcp.record_case_decision(
            "SSP26000001", "REJECTED", "ok", True)
        self.assertFalse(result["recorded"])
        self.assertEqual(result["error"], "decision_reason_required")

    def test_only_approve_or_reject_are_supported(self):
        result = officer_mcp.record_case_decision(
            "SSP26000001", "DEEMED_APPROVED", "Documents verified", True)
        self.assertFalse(result["recorded"])
        self.assertEqual(result["error"], "invalid_decision")


if __name__ == "__main__":
    unittest.main()
