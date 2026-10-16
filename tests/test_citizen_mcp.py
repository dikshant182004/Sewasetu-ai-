"""Focused authentication-boundary tests for the citizen MCP service.

These tests verify JWT claim enforcement without a running database. Submission and
portal-visibility tests must additionally run against a disposable PostgreSQL stack.
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

import citizen_mcp  # noqa: E402


class CitizenTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.private.public_key()))
        jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
        cls.jwks = {"keys": [jwk]}
        citizen_mcp._jwks_cache = None
        cls.original_jwks = citizen_mcp._jwks
        citizen_mcp._jwks = lambda: cls.jwks

    @classmethod
    def tearDownClass(cls):
        citizen_mcp._jwks = cls.original_jwks
        citizen_mcp._jwks_cache = None

    def token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": citizen_mcp.ISSUER,
            "aud": citizen_mcp.AUDIENCE,
            "sub": "citizen:9000000001",
            "role": "citizen",
            "scope": "citizen",
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private, algorithm="RS256", headers={"kid": "test-key"})

    def test_rfc9728_metadata_is_path_specific(self):
        from urllib.parse import urlsplit
        resource = urlsplit(citizen_mcp.AUDIENCE)
        self.assertEqual(citizen_mcp.RESOURCE_METADATA_PATH,
                         "/.well-known/oauth-protected-resource" + resource.path.rstrip("/"))
        metadata = urlsplit(citizen_mcp.RESOURCE_METADATA_URL)
        self.assertEqual((metadata.scheme, metadata.netloc), (resource.scheme, resource.netloc))
        self.assertEqual(metadata.path, citizen_mcp.RESOURCE_METADATA_PATH)

    def test_valid_citizen_token_is_accepted(self):
        claims = citizen_mcp.verify_bearer("Bearer " + self.token())
        self.assertEqual(claims["sub"], "citizen:9000000001")
        token = citizen_mcp._claims.set(claims)
        try:
            self.assertEqual(citizen_mcp.citizen_mobile(), "9000000001")
        finally:
            citizen_mcp._claims.reset(token)

    def test_wrong_audience_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer("Bearer " + self.token(aud="http://other.example/mcp"))

    def test_wrong_issuer_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer("Bearer " + self.token(iss="https://attacker.example"))

    def test_officer_role_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer("Bearer " + self.token(role="officer", scope="officer",
                                                               sub="officer:admin"))

    def test_wrong_scope_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer("Bearer " + self.token(scope="openid profile"))

    def test_malformed_subject_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer("Bearer " + self.token(sub="citizen:123"))

    def test_expired_token_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer("Bearer " + self.token(exp=int(time.time()) - 60,
                                                               iat=int(time.time()) - 120))

    def test_missing_bearer_is_rejected(self):
        with self.assertRaises(citizen_mcp.AuthError):
            citizen_mcp.verify_bearer(None)


if __name__ == "__main__":
    unittest.main()
