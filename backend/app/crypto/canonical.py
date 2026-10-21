"""
crypto.canonical — Canonical JSON serializer for digital signatures.

Crypto concept: Deterministic serialization (JSON Canonicalization Scheme).
Threat mitigated: Signature invalidation due to whitespace, key ordering,
or Unicode normalization differences between client and server.

Rules:
1. UTF-8 encoded.
2. Object keys sorted lexicographically.
3. No insignificant whitespace (separators: ',', ':').
4. Integers only — floats are strictly prohibited to prevent IEEE-754 precision mismatches.
5. Strings are Unicode NFC normalized.
6. Booleans serialized as 'true' / 'false', None as 'null'.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any


def _normalize_obj(obj: Any) -> Any:
    """Recursively normalize objects for canonical serialization."""
    if isinstance(obj, float):
        raise ValueError(
            f"Floats are prohibited in canonical JSON (got {obj}). Use integer paise."
        )
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        # Sort keys lexicographically
        return {
            unicodedata.normalize("NFC", str(k)): _normalize_obj(v)
            for k, v in sorted(obj.items(), key=lambda item: str(item[0]))
        }
    if isinstance(obj, (list, tuple)):
        return [_normalize_obj(item) for item in obj]
    if isinstance(obj, (int, bool)) or obj is None:
        return obj
    # Fallback: if object has a dict representation or str
    if hasattr(obj, "to_dict"):
        return _normalize_obj(obj.to_dict())
    if hasattr(obj, "__dict__"):
        return _normalize_obj(obj.__dict__)
    return str(obj)


def canonical_json_str(obj: Any) -> str:
    """Serialize an object to a canonical JSON string."""
    normalized = _normalize_obj(obj)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        indent=None,
        separators=(",", ":"),
    )


def canonical_json(obj: Any) -> bytes:
    """Serialize an object to canonical UTF-8 bytes for hashing/signing."""
    return canonical_json_str(obj).encode("utf-8")


canonical_json_bytes = canonical_json
