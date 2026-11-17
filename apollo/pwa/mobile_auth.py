# -*- coding: utf-8 -*-
"""Helpers for signing observers in from the DEOW mobile app.

The mobile app authenticates with ``DEOW_API_KEY`` and passes the logged-in observer's verified
phone number (WordPress ``user.phone`` / ``user_login``). Apollo verifies the API key and matches
the phone number to participant phone contacts in the current event.

This module uses only the Python standard library so it can be unit tested in isolation.
"""
import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, Optional

# number of trailing digits compared when matching phone numbers; this makes
# "0911223344", "+251911223344" and "251 91 122 3344" equivalent
PHONE_MATCH_DIGITS = 9
_NON_DIGITS = re.compile(r"[^0-9]")
_LEEWAY_SECONDS = 60


class MobileAuthError(Exception):
    """Raised when the mobile sign-in request cannot be authenticated."""

    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.message = message
        self.status = status


def verify_deow_api_key(provided_key: Optional[str], expected_key: Optional[str]) -> None:
    """Verify the DEOW API key using constant-time comparison."""
    expected = (expected_key or "").strip()
    if not expected:
        raise MobileAuthError("Mobile sign-in is not configured", status=503)

    provided = (provided_key or "").strip()
    if not provided:
        raise MobileAuthError("Missing API key")

    if not hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        raise MobileAuthError("Invalid API key")


def resolve_observer_phone(phone_value: Optional[str]) -> str:
    """Validate and return the observer's phone number from the request."""
    if not isinstance(phone_value, str) or not phone_value.strip():
        raise MobileAuthError("Missing observer phone number")

    cleaned = phone_value.strip()
    if phone_match_key(cleaned) is None:
        raise MobileAuthError("Invalid observer phone number")

    return cleaned


def extract_bearer_token(header_value: Optional[str]) -> str:
    """Return the token from an ``Authorization: Bearer <token>`` header."""
    if not header_value:
        raise MobileAuthError("Missing authorization header")

    parts = header_value.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise MobileAuthError("Invalid authorization header")

    return parts[1].strip()


def _b64url_decode(data: str) -> bytes:
    rem = len(data) % 4
    if rem == 1:
        raise MobileAuthError("Invalid token")
    if rem:
        data += "=" * (4 - rem)
    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise MobileAuthError("Invalid token") from None


def verify_wp_token(token: str, secret: str, issuer: str = "") -> Dict[str, Any]:
    """Verify a WordPress-issued HS256 JWT and return its claims."""
    raw_candidates = [s.strip().lstrip("/") for s in (secret or "").split("||") if s.strip()]
    candidates = []
    for cand in raw_candidates:
        for variant in (cand, cand.replace("$$", "$")):
            if variant and variant not in candidates:
                candidates.append(variant)
    if not candidates:
        raise MobileAuthError("Mobile sign-in is not configured", status=503)

    if not isinstance(token, str):
        raise MobileAuthError("Invalid token")

    parts = token.split(".")
    if len(parts) != 3:
        raise MobileAuthError("Invalid token")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise MobileAuthError("Invalid token") from None

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise MobileAuthError("Invalid token")

    if header.get("alg") != "HS256":
        raise MobileAuthError("Invalid token")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    actual_sig = _b64url_decode(sig_b64)

    matched = False
    for candidate in candidates:
        expected_sig = hmac.new(candidate.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(expected_sig, actual_sig):
            matched = True
            break

    if not matched:
        raise MobileAuthError("Token signature mismatch")

    now = time.time()
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise MobileAuthError("Invalid token")
    if now > exp + _LEEWAY_SECONDS:
        raise MobileAuthError("Token expired")

    nbf = claims.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)) or isinstance(nbf, bool) or now + _LEEWAY_SECONDS < nbf:
            raise MobileAuthError("Invalid token")

    if issuer and claims.get("iss") != issuer:
        raise MobileAuthError("Invalid token")

    return claims


def phone_from_claims(claims: Dict[str, Any]) -> str:
    """Get the observer's phone (WordPress username) from either token layout."""
    username = None
    data = claims.get("data")
    if isinstance(data, dict) and isinstance(data.get("user"), dict):
        username = data["user"].get("username")
    if not username:
        username = claims.get("username")

    if not isinstance(username, str) or not username.strip():
        raise MobileAuthError("Token has no user")

    return username.strip()


def phone_match_key(phone: str) -> Optional[str]:
    """Return the trailing digits used to compare phone numbers, or ``None`` if there are too few."""
    digits = _NON_DIGITS.sub("", phone or "")
    if len(digits) < PHONE_MATCH_DIGITS:
        return None

    return digits[-PHONE_MATCH_DIGITS:]


def mask_phone(phone: str) -> str:
    """Mask a phone number for logging, keeping only the last 3 digits."""
    digits = _NON_DIGITS.sub("", phone or "")
    return ("*" * max(len(digits) - 3, 0)) + digits[-3:]
