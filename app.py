"""
Jack Remote Decryptor
=====================
Holds ii.so on the server side.
Client sends ciphertexts, receives plaintexts.
"""
import ctypes
import hashlib
import hmac
import json
import logging
import os
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("jack")


# ------------------------------------------------------------------
# Load ii.so
# ------------------------------------------------------------------
_II_PATH = Path(__file__).parent / "ii.so"
if not _II_PATH.exists():
    raise RuntimeError(f"ii.so not found at {_II_PATH}")

log.info("loading ii.so from %s", _II_PATH)
_lib = ctypes.CDLL(str(_II_PATH))
_lib._x2z.restype = ctypes.c_void_p
_lib._x2z.argtypes = [ctypes.c_char_p, ctypes.c_int]
_lib._x2O.restype = None
_lib._x2O.argtypes = [ctypes.c_void_p]
log.info("ii.so loaded successfully")


def _decrypt_one(payload: str) -> str:
    """Decrypt one base64 payload via ii.so."""
    if not payload:
        return ""
    raw = payload.encode("ascii", "ignore")
    ptr = _lib._x2z(raw, len(raw))
    if not ptr:
        return ""
    try:
        return ctypes.string_at(ptr).decode("utf-8", "ignore")
    finally:
        _lib._x2O(ptr)


# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
API_SECRET = os.environ.get("API_SECRET", "").encode()
if len(API_SECRET) < 32:
    raise RuntimeError("API_SECRET env var missing or too short (need >=32 chars)")

MAX_SKEW_MS = 60_000
RATE_LIMIT = 240
RATE_WINDOW = 60
MAX_BATCH = 64

_rate: dict[str, list[float]] = defaultdict(list)


def _check_rate(ip: str) -> bool:
    now = time.time()
    cutoff = now - RATE_WINDOW
    bucket = _rate[ip]
    bucket[:] = [t for t in bucket if t > cutoff]
    if len(bucket) >= RATE_LIMIT:
        return False
    bucket.append(now)
    return True


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def _verify(body: dict, ts: int, sig: str) -> bool:
    if abs(time.time() * 1000 - ts) > MAX_SKEW_MS:
        return False
    payload = _canonical(body) + b"|" + str(ts).encode()
    expected = hmac.new(API_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


# ------------------------------------------------------------------
# FastAPI
# ------------------------------------------------------------------
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


class DecryptRequest(BaseModel):
    items: list[str] = Field(..., min_length=1, max_length=MAX_BATCH)
    ts: int
    sig: str = Field(..., min_length=64, max_length=64)


@app.get("/")
def root():
    return {"status": "ok", "service": "jack-remote"}


@app.get("/health")
def health():
    return {"status": "alive", "t": int(time.time())}


@app.post("/decrypt")
async def decrypt(req: DecryptRequest, request: Request):
    ip = request.client.host if request.client else "unknown"

    if not _check_rate(ip):
        log.warning("rate_limit ip=%s", ip)
        raise HTTPException(429, "rate limit exceeded")

    body = {"items": req.items}
    if not _verify(body, req.ts, req.sig):
        log.warning("bad_sig ip=%s", ip)
        raise HTTPException(403, "forbidden")

    results = []
    for item in req.items:
        try:
            results.append(_decrypt_one(item))
        except Exception:
            log.exception("decrypt error")
            results.append("")

    log.info("ok ip=%s n=%d", ip, len(results))
    return JSONResponse({"results": results})