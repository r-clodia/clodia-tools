"""Minimal AWS Signature Version 4, for one S3 PUT.

The gateway has no AWS SDK, and adding one for a single request is a large
dependency for a small need. This is the documented algorithm
(https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html),
tested against the worked example of that documentation. It works with any
S3-compatible endpoint that implements SigV4 and Object Lock.
"""
from __future__ import annotations

import hashlib
import hmac
from urllib.parse import quote


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def canonical_query(query: dict[str, str]) -> str:
    return "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
                    for k, v in sorted(query.items()))


def sign(method: str, host: str, path: str, query: dict[str, str],
         headers: dict[str, str], payload: bytes, *, access_key: str,
         secret_key: str, region: str, service: str, amz_date: str) -> dict[str, str]:
    """Return `headers` plus `x-amz-date` and `Authorization`.

    `headers` must not contain `host` or `x-amz-date`: both are added here and
    signed. `path` must already be URI-encoded.
    """
    date = amz_date[:8]
    hdrs = {k.lower().strip(): " ".join(str(v).split()) for k, v in headers.items()}
    hdrs["host"] = host
    hdrs["x-amz-date"] = amz_date
    signed = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs))
    payload_hash = hdrs.get("x-amz-content-sha256") or _h(payload)
    canonical_request = "\n".join([method, path or "/", canonical_query(query),
                                   canonical_headers, signed, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, _h(canonical_request.encode())])
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    k = _hmac(k, "aws4_request")
    signature = hmac.new(k, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = {k2: v for k2, v in headers.items()}
    out["x-amz-date"] = amz_date
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                            f"SignedHeaders={signed}, Signature={signature}")
    return out
