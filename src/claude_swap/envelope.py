"""Passphrase-encrypted wrapper for the export envelope (scrypt + AES-256-GCM).

The plaintext envelope carries live OAuth refresh tokens, so authorized
transfers should use this mode. ``cryptography`` is an optional dependency
(``pip install claude-swap[envelope]``) and is imported lazily.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from claude_swap.exceptions import TransferError

PASSPHRASE_ENV = "CSWAP_ENVELOPE_PASSPHRASE"
REQUIRE_ENCRYPTED_ENV = "CSWAP_REQUIRE_ENCRYPTED_EXPORT"
_AAD_PREFIX = b"claude-swap-envelope-v1"
_SCRYPT = {"n": 2**15, "r": 8, "p": 1}
_MIN_PASSPHRASE = 12


def require_encrypted() -> bool:
    return os.environ.get(REQUIRE_ENCRYPTED_ENV, "").strip().lower() in {"1", "true", "yes"}


def resolve_passphrase(passphrase_file: str | None) -> str:
    """Read the passphrase from a 0600 file or the environment; never argv."""
    if passphrase_file:
        path = Path(passphrase_file).expanduser()
        try:
            if os.name != "nt" and path.stat().st_mode & 0o077:
                raise TransferError(
                    f"passphrase file {path} must not be group/world accessible (chmod 600)"
                )
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise TransferError(f"cannot read passphrase file: {exc.strerror}")
    else:
        value = os.environ.get(PASSPHRASE_ENV, "")
    if not value:
        raise TransferError(
            f"a passphrase is required: use --passphrase-file or set {PASSPHRASE_ENV}"
        )
    return value


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise TransferError(
            "encrypted envelopes need the 'cryptography' package: "
            "pip install 'claude-swap[envelope]'"
        )
    return AESGCM


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p,
        maxmem=256 * 1024 * 1024, dklen=32,
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _aad(wrapper: dict) -> bytes:
    """Bind the cleartext header fields to the ciphertext."""
    header = {k: wrapper.get(k) for k in ("version", "encrypted", "exportedAt", "cipher", "kdf", "nonce")}
    return _AAD_PREFIX + json.dumps(header, sort_keys=True).encode("utf-8")


def encrypt_envelope(envelope: dict, passphrase: str) -> dict:
    if len(passphrase) < _MIN_PASSPHRASE:
        raise TransferError(f"passphrase must be at least {_MIN_PASSPHRASE} characters")
    aesgcm = _aesgcm()
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt, **_SCRYPT)
    plaintext = json.dumps(envelope).encode("utf-8")
    wrapper = {
        "version": envelope["version"],
        "encrypted": True,
        "exportedAt": envelope.get("exportedAt"),
        "cipher": "aes-256-gcm",
        "kdf": {"name": "scrypt", **_SCRYPT, "salt": _b64(salt)},
        "nonce": _b64(nonce),
    }
    wrapper["ciphertext"] = _b64(aesgcm(key).encrypt(nonce, plaintext, _aad(wrapper)))
    return wrapper


def decrypt_envelope(wrapper: dict, passphrase: str) -> dict:
    aesgcm = _aesgcm()
    try:
        kdf = wrapper["kdf"]
        if wrapper.get("cipher") != "aes-256-gcm" or kdf.get("name") != "scrypt":
            raise TransferError("unsupported encrypted envelope cipher/kdf")
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        if n > 2**20 or r > 16 or p > 4:  # bound attacker-chosen KDF cost
            raise TransferError("encrypted envelope KDF parameters out of range")
        key = _derive(passphrase, base64.b64decode(kdf["salt"]), n, r, p)
        plaintext = aesgcm(key).decrypt(
            base64.b64decode(wrapper["nonce"]),
            base64.b64decode(wrapper["ciphertext"]),
            _aad(wrapper),
        )
        inner = json.loads(plaintext)
    except TransferError:
        raise
    except Exception:
        # Deliberately generic: never echo payload or crypto internals.
        raise TransferError("cannot decrypt envelope: wrong passphrase or corrupted file")
    if not isinstance(inner, dict):
        raise TransferError("decrypted envelope must be a JSON object")
    return inner
