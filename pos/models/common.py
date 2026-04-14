from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PublicParameters:
    security_parameter: int
    p: int
    q: int
    G: Any
    G_prime: Any
    g: int
    h: int
    g_prime: int
    k: int
    m: int
    N: int
    sigma: float
    mu: float
    hash_name: str
    ticket_nonce_bytes: int
    proof_share_count: int
    proof_recover_threshold: int
    serialization_byte_order: str
    serialization_length_bytes: int
    ticket_version: int