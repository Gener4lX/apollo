# -*- coding: utf-8 -*-
import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, Optional
PHONE_MATCH_DIGITS = 9
_NON_DIGITS = re.compile(r"[^0-9]")
_LEEWAY_SECONDS = 60
class MobileAuthError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.message = message
        self.status = status
def extract_bearer_token(header_value: Optional[str]) -> str:
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
        raise MobileAuthError("Invalid token format")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise MobileAuthError("Invalid token payload") from None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise MobileAuthError("Invalid token claims")
    if header.get("alg") != "HS256":
        raise MobileAuthError("Unsupported token algorithm")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    actual_sig = _b64url_decode(sig_b64)
    matched = False
    for candidate in candidates:
        expected_sig = hmac.new(candidate.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(expected_sig, actual_sig):
            matched = True
            break
    if not matched:
        raise MobileAuthError(f"Token signature mismatch (iss={claims.get('iss')})")
    now = time.time()
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise MobileAuthError("Token missing exp")
    if now > exp + _LEEWAY_SECONDS:
        raise MobileAuthError("Token expired")
    if issuer and claims.get("iss") != issuer:
        raise MobileAuthError("Token issuer mismatch")
    return claims
def phone_from_claims(claims: Dict[str, Any]) -> str:
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
    digits = _NON_DIGITS.sub("", phone or "")
    if len(digits) < PHONE_MATCH_DIGITS:
        return None
    return digits[-PHONE_MATCH_DIGITS:]
def mask_phone(phone: str) -> str:
    digits = _NON_DIGITS.sub("", phone or "")
    return ("*" * max(len(digits) - 3, 0)) + digits[-3:]
