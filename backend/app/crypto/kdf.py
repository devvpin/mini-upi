"""
crypto.kdf — Argon2id password and MPIN hashing with HMAC pre-hashing.

Crypto concept: Memory-hard password hashing (Argon2id) with server-side pepper pre-hashing
via HMAC-SHA256. Argon2id combines Argon2d (data-dependent memory access resisting GPU cracking)
and Argon2i (data-independent memory access resisting side-channel cache attacks).

Threat mitigated: Offline dictionary, brute-force, rainbow table, and GPU cracking attacks
if the database is leaked. Even with the DB hash, an attacker without the server pepper cannot
compute the Argon2 input.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

import argon2
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Tunable Argon2id parameters (per brain/05_CRYPTO_DESIGN.md)
# Memory cost in KiB (64 MiB = 65,536 KiB)
DEFAULT_TIME_COST: Final[int] = 3
DEFAULT_MEMORY_COST: Final[int] = 65_536
DEFAULT_PARALLELISM: Final[int] = 2
DEFAULT_HASH_LEN: Final[int] = 32
DEFAULT_SALT_LEN: Final[int] = 16

_hasher = argon2.PasswordHasher(
    time_cost=DEFAULT_TIME_COST,
    memory_cost=DEFAULT_MEMORY_COST,
    parallelism=DEFAULT_PARALLELISM,
    hash_len=DEFAULT_HASH_LEN,
    salt_len=DEFAULT_SALT_LEN,
    type=argon2.Type.ID,
)


def _prehash(secret: str, pepper: str) -> bytes:
    """Pre-hash the secret with server pepper using HMAC-SHA256."""
    return hmac.new(
        key=pepper.encode("utf-8"),
        msg=secret.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()


def hash_secret(
    secret: str,
    pepper: str,
    *,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost: int = DEFAULT_MEMORY_COST,
    parallelism: int = DEFAULT_PARALLELISM,
) -> str:
    """Hash a password or MPIN using HMAC-SHA256 pre-hash followed by Argon2id."""
    if not pepper:
        raise ValueError("Server pepper must not be empty.")
    hasher = (
        _hasher
        if (
            time_cost == DEFAULT_TIME_COST
            and memory_cost == DEFAULT_MEMORY_COST
            and parallelism == DEFAULT_PARALLELISM
        )
        else argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=DEFAULT_HASH_LEN,
            salt_len=DEFAULT_SALT_LEN,
            type=argon2.Type.ID,
        )
    )
    prehashed = _prehash(secret, pepper)
    return hasher.hash(prehashed)


def verify_secret(secret: str, hashed: str, pepper: str) -> bool:
    """
    Verify a secret against an Argon2id hash using constant-time comparison.
    Returns True if valid, False otherwise.
    """
    if not pepper:
        return False
    prehashed = _prehash(secret, pepper)
    try:
        return _hasher.verify(hashed, prehashed)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """Check if the hash was created with older parameters and needs updating."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True


# Pre-computed dummy hash using the default hasher for timing equalization
# Generated with a random dummy secret and dummy pepper
DUMMY_HASH: Final[str] = (
    "$argon2id$v=19$m=65536,t=3,p=2$"
    "NzJzZkQ3azFqUG9yVzF4eA$"
    "FkYx9y9J40J19pC7P4Y1G3N+u8M8hR/N4X7hZ6X+gZ0"
)


def verify_dummy(pepper: str) -> bool:
    """
    Perform a dummy verification to equalize execution time when an account
    does not exist, preventing timing enumeration attacks.
    """
    import contextlib

    prehashed = _prehash("invalid_dummy_credential", pepper)
    with contextlib.suppress(Exception):
        _hasher.verify(DUMMY_HASH, prehashed)
    return False
