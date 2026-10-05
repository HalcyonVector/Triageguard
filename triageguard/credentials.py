"""Find and decode JWTs, OAuth/API tokens and OTP (TOTP/HOTP) secrets.

Secrets are never stored in full: we keep a redacted preview and a SHA-256
so findings can be correlated without leaking the credential.
"""

import base64
import hashlib
import json
import mmap
import re
import time
from urllib.parse import parse_qs, unquote, urlparse

JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
OTP_RE = re.compile(rb"otpauth://(?:totp|hotp)/[^\s\x00\"'<>]{1,300}")
TOKEN_RES = {
    "Google OAuth access token": re.compile(rb"ya29\.[0-9A-Za-z_-]{20,}"),
    "GitHub token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{36}"),
    "Slack token": re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "AWS access key id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "Bearer token": re.compile(rb"Bearer\s+([A-Za-z0-9._~+/-]{20,}=*)"),
    "OAuth refresh token": re.compile(rb"refresh_token[\"'=:\s]+([A-Za-z0-9._~+/-]{16,})"),
}
MAX_PER_TYPE = 50


def redact(s):
    return s[:6] + "..." + s[-4:] if len(s) > 14 else s[:3] + "..."


def _b64url(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def decode_jwt(token):
    h, p, sig = token.split(".")
    header, payload = json.loads(_b64url(h)), json.loads(_b64url(p))
    issues = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none" or not sig:
        issues.append("unsigned token (alg=none): signature not verified, trivially forgeable")
    elif alg.startswith("hs"):
        issues.append(f"symmetric {header['alg']}: security rests on secret strength; offline guessing possible")
    if "exp" not in payload:
        issues.append("no expiry (exp) claim")
    elif isinstance(payload["exp"], (int, float)) and payload["exp"] < time.time():
        issues.append("token expired")
    # payload values may be personal data; keep claim names and a few safe fields
    safe = {k: payload[k] for k in ("iss", "aud", "exp", "iat", "scope") if k in payload}
    return {"header": header, "claims": sorted(payload), "safe_claims": safe, "issues": issues}


def decode_otp(uri):
    u = urlparse(uri)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    secret = q.get("secret", "")
    issues = []
    try:
        raw = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
        bits = len(raw) * 8
        if bits < 128:
            issues.append(f"secret is {bits} bits; RFC 4226 requires at least 128 (160 recommended)")
    except Exception:
        bits = None
        issues.append("secret is not valid base32")
    algo = q.get("algorithm", "SHA1").upper()
    if algo == "SHA1":
        issues.append("HMAC-SHA1 (default); acceptable for HOTP but SHA-256 preferred")
    return {"type": u.netloc, "label": unquote(u.path.lstrip("/")), "issuer": q.get("issuer"),
            "algorithm": algo, "digits": int(q.get("digits", 6)), "period": int(q.get("period", 30)),
            "secret_bits": bits, "issues": issues}


def scan(path):
    findings = []
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        seen = set()

        def add(kind, offset, value, decoded=None):
            digest = hashlib.sha256(value.encode()).hexdigest()
            if digest in seen:
                return
            seen.add(digest)
            findings.append({"type": kind, "offset": hex(offset), "preview": redact(value),
                             "sha256": digest[:16], "decoded": decoded})

        for i, m in enumerate(JWT_RE.finditer(mm)):
            if i >= MAX_PER_TYPE:
                break
            tok = m.group(0).decode()
            try:
                add("JWT", m.start(), tok, decode_jwt(tok))
            except Exception:
                continue
        for i, m in enumerate(OTP_RE.finditer(mm)):
            if i >= MAX_PER_TYPE:
                break
            uri = m.group(0).decode(errors="replace")
            add("OTP secret (otpauth URI)", m.start(), uri, decode_otp(uri))
        for kind, rx in TOKEN_RES.items():
            for i, m in enumerate(rx.finditer(mm)):
                if i >= MAX_PER_TYPE:
                    break
                add(kind, m.start(), m.group(m.lastindex or 0).decode(errors="replace"))
    return findings
