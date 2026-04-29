from __future__ import annotations

import os


def strict_kms_patent_mode_enabled() -> bool:
    return (
        os.environ.get("POS_STRICT_PATENT_MODE", "").strip().lower()
        in {"1", "true", "yes", "on"}
        and os.environ.get("POS_FHE_BACKEND", "").strip().lower() == "kms-threshold"
    )


def _parse_bits_env(name: str, default: int, allowed: set[int]) -> int:
    value = int(os.environ.get(name, str(default)))
    if value not in allowed:
        raise ValueError(f"{name} must be one of {sorted(allowed)}, got {value}")
    return value


def lottery_word_bits() -> int:
    """
    Width for patent election arithmetic:
      - encrypted stake
      - encrypted PRF share
      - total/cumulative stake
      - scaled random
      - Ccompare inputs

    Default 32 bits is the current patent-integration target. Production can
    raise this once KMS evaluator support is extended further.
    """
    if strict_kms_patent_mode_enabled():
        return _parse_bits_env("POS_LOTTERY_WORD_BITS", 32, {8, 16, 32})
    return 16


def ticket_chunk_bits() -> int:
    """
    Width for encrypted ticket hash suffix chunks.

    The patent requires encrypting the second half of the ticket hash. It does
    not require one ciphertext to contain the whole suffix, so 16-bit chunks are
    used by default: SHA-256 suffix 128 bits -> 8 encrypted euint16 chunks.
    """
    if strict_kms_patent_mode_enabled():
        return _parse_bits_env("POS_TICKET_CHUNK_BITS", 16, {8, 16, 32})
    return 16


def lottery_data_type() -> str:
    return f"euint{lottery_word_bits()}"


def ticket_data_type() -> str:
    return f"euint{ticket_chunk_bits()}"


def lottery_modulus() -> int:
    return 1 << lottery_word_bits()


def ticket_chunk_bytes() -> int:
    bits = ticket_chunk_bits()
    if bits % 8 != 0:
        raise ValueError(f"ticket chunk bits must be byte-aligned, got {bits}")
    return bits // 8


def ticket_encoding_family() -> str:
    return {
        1: "hex_suffix_byte",
        2: "hex_suffix_word",
        4: "hex_suffix_dword",
    }[ticket_chunk_bytes()]
