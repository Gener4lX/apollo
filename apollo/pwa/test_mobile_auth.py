# -*- coding: utf-8 -*-
import base64
import hashlib
import hmac
import json
import time
import unittest

try:
    from apollo.pwa.mobile_auth import (
        MobileAuthError,
        extract_bearer_token,
        mask_phone,
        phone_from_claims,
        phone_match_key,
        verify_wp_token,
    )
except ModuleNotFoundError:
    from mobile_auth import (  # type: ignore[no-redef]
        MobileAuthError,
        extract_bearer_token,
        mask_phone,
        phone_from_claims,
        phone_match_key,
        verify_wp_token,
    )

SECRET = "test-wordpress-secret-key-1234567890"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _token(claims=None, secret=SECRET, algorithm="HS256"):
    header = {"typ": "JWT", "alg": algorithm}
    payload = {"iat": int(time.time()), "exp": int(time.time()) + 3600}
    if claims is not None:
        payload.update(claims)
    header_b64 = _b64url(json.dumps(header).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if algorithm == "none":
        sig_b64 = ""
    elif algorithm == "HS512":
        sig_b64 = _b64url(hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha512).digest())
    else:
        sig_b64 = _b64url(hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest())
    return f"{header_b64}.{payload_b64}.{sig_b64}"


class TestExtractBearerToken(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(extract_bearer_token("Bearer abc.def.ghi"), "abc.def.ghi")
        self.assertEqual(extract_bearer_token("bearer   abc"), "abc")

    def test_invalid(self):
        for value in [None, "", "Bearer", "Bearer   ", "Basic abc", "abc"]:
            with self.subTest(value=value):
                with self.assertRaises(MobileAuthError):
                    extract_bearer_token(value)


class TestVerifyWpToken(unittest.TestCase):
    def test_valid_token(self):
        claims = verify_wp_token(_token({"username": "0911223344"}), SECRET)
        self.assertEqual(claims["username"], "0911223344")

    def test_expired_token(self):
        with self.assertRaisesRegex(MobileAuthError, "expired"):
            verify_wp_token(_token({"exp": int(time.time()) - 3600}), SECRET)

    def test_token_without_expiry_is_rejected(self):
        header_b64 = _b64url(json.dumps({"typ": "JWT", "alg": "HS256"}).encode("utf-8"))
        payload_b64 = _b64url(json.dumps({"username": "0911223344"}).encode("utf-8"))
        sig_b64 = _b64url(
            hmac.new(SECRET.encode("utf-8"), f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256).digest()
        )
        with self.assertRaises(MobileAuthError):
            verify_wp_token(f"{header_b64}.{payload_b64}.{sig_b64}", SECRET)

    def test_wrong_secret(self):
        with self.assertRaises(MobileAuthError):
            verify_wp_token(_token(secret="another-secret-key-0123456789abcdef"), SECRET)

    def test_other_hmac_algorithm_is_rejected(self):
        with self.assertRaises(MobileAuthError):
            verify_wp_token(_token(algorithm="HS512"), SECRET)

    def test_unsigned_token_is_rejected(self):
        with self.assertRaises(MobileAuthError):
            verify_wp_token(_token({"username": "0911223344"}, algorithm="none"), SECRET)

    def test_garbage_token(self):
        with self.assertRaises(MobileAuthError):
            verify_wp_token("not-a-token", SECRET)

    def test_not_configured(self):
        with self.assertRaises(MobileAuthError) as ctx:
            verify_wp_token(_token(), "")
        self.assertEqual(ctx.exception.status, 503)

    def test_issuer_checked_only_when_configured(self):
        token = _token({"iss": "https://deow-cecoe.org"})
        self.assertEqual(verify_wp_token(token, SECRET)["iss"], "https://deow-cecoe.org")
        self.assertTrue(verify_wp_token(token, SECRET, "https://deow-cecoe.org"))
        with self.assertRaises(MobileAuthError):
            verify_wp_token(token, SECRET, "https://other.example")


class TestPhoneFromClaims(unittest.TestCase):
    def test_plugin_layout(self):
        self.assertEqual(
            phone_from_claims({"data": {"user": {"id": 5, "username": " 0911223344 "}}}),
            "0911223344",
        )

    def test_custom_layout(self):
        self.assertEqual(phone_from_claims({"user_id": 5, "username": "0911223344"}), "0911223344")

    def test_missing_user(self):
        for claims in [{}, {"username": ""}, {"data": {"user": {}}}, {"username": 5}]:
            with self.subTest(claims=claims):
                with self.assertRaises(MobileAuthError):
                    phone_from_claims(claims)


class TestPhoneMatchKey(unittest.TestCase):
    def test_equivalent_formats(self):
        for phone in ["0911223344", "+251911223344", "251 91 122 3344", "(251)-911-22-33-44", "00251911223344"]:
            with self.subTest(phone=phone):
                self.assertEqual(phone_match_key(phone), "911223344")

    def test_too_short(self):
        for phone in ["", None, "12345", "abc"]:
            with self.subTest(phone=phone):
                self.assertIsNone(phone_match_key(phone))

    def test_different_numbers_differ(self):
        self.assertNotEqual(phone_match_key("0911223344"), phone_match_key("0911223345"))

    def test_mask_phone(self):
        self.assertEqual(mask_phone("0911223344"), "*******344")
        self.assertEqual(mask_phone("12"), "12")
        self.assertEqual(mask_phone(""), "")


if __name__ == "__main__":
    unittest.main()
