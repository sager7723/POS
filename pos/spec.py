from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from typing import Callable


@dataclass(frozen=True)
class SecurityProfile:
    security_parameter: int
    group_name: str
    p: int
    q: int
    hash_name: str
    k: int
    m: int
    N: int
    sigma: float
    mu: float
    quantization_step: float
    ticket_nonce_bytes: int
    proof_share_count: int
    proof_recover_threshold: int
    serialization_byte_order: str = "big"
    serialization_length_bytes: int = 4
    participant_threshold_ratio: tuple[int, int] = (2, 3)


RFC3526_GROUP14_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

RFC3526_GROUP15_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)


def _derive_q(p: int) -> int:
    return (p - 1) // 2


SECURITY_PROFILES: dict[int, SecurityProfile] = {
    128: SecurityProfile(
        security_parameter=128,
        group_name="rfc3526-group14-safe-prime",
        p=RFC3526_GROUP14_P,
        q=_derive_q(RFC3526_GROUP14_P),
        hash_name="sha256",
        k=630,
        m=4096,
        N=1024,
        sigma=3.2,
        mu=0.0,
        quantization_step=2.0,
        ticket_nonce_bytes=32,
        proof_share_count=5,
        proof_recover_threshold=3,
    ),
    192: SecurityProfile(
        security_parameter=192,
        group_name="rfc3526-group15-safe-prime",
        p=RFC3526_GROUP15_P,
        q=_derive_q(RFC3526_GROUP15_P),
        hash_name="sha384",
        k=750,
        m=6144,
        N=2048,
        sigma=3.2,
        mu=0.0,
        quantization_step=2.0,
        ticket_nonce_bytes=48,
        proof_share_count=7,
        proof_recover_threshold=4,
    ),
}

SUPPORTED_SECURITY_PARAMETERS = tuple(sorted(SECURITY_PROFILES.keys()))

HASHLIB_BY_NAME: dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def resolve_security_profile(security_parameter: int) -> SecurityProfile:
    if security_parameter <= 128:
        return SECURITY_PROFILES[128]
    if security_parameter <= 192:
        return SECURITY_PROFILES[192]
    raise ValueError(
        f"Unsupported security parameter: {security_parameter}. "
        "Supported maximum is 192 in the current phase-0 configuration."
    )


def get_hash_function(hash_name: str) -> Callable[[bytes], "hashlib._Hash"]:
    try:
        return HASHLIB_BY_NAME[hash_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported hash function: {hash_name}") from exc


def recommend_decryption_threshold(participant_count: int) -> int:
    if participant_count <= 0:
        raise ValueError("participant_count must be positive")
    return max(2, math.ceil((2 * participant_count) / 3))


def compute_noise_bound(profile: SecurityProfile) -> float:
    return profile.quantization_step / 2.0


def int_to_fixed_length_bytes(value: int, length_bytes: int, byte_order: str) -> bytes:
    return value.to_bytes(length_bytes, byte_order, signed=False)


def encode_length_prefixed_bytes(data: bytes, length_bytes: int, byte_order: str) -> bytes:
    if len(data) >= 1 << (8 * length_bytes):
        raise ValueError("data too large for configured length prefix")
    return int_to_fixed_length_bytes(len(data), length_bytes, byte_order) + data


def encode_ticket_preimage(
    participant_id: str,
    nonce: bytes,
    version: int,
    length_bytes: int,
    byte_order: str,
) -> bytes:
    participant_bytes = participant_id.encode("utf-8")
    payload = bytearray()
    payload.extend(b"PSSLE-TICKET")
    payload.extend(int_to_fixed_length_bytes(version, 1, byte_order))
    payload.extend(encode_length_prefixed_bytes(participant_bytes, length_bytes, byte_order))
    payload.extend(encode_length_prefixed_bytes(nonce, length_bytes, byte_order))
    return bytes(payload)


def split_digest_hex(digest_hex: str) -> tuple[str, str]:
    midpoint = len(digest_hex) // 2
    return digest_hex[:midpoint], digest_hex[midpoint:]


def hash_bytes(data: bytes, hash_name: str) -> str:
    return get_hash_function(hash_name)(data).hexdigest()


def derive_generator_of_order_q(p: int, q: int, domain_label: str) -> int:
    seed = 1
    while True:
        candidate_bytes = hashlib.sha256(f"{domain_label}:{seed}".encode("utf-8")).digest()
        candidate = int.from_bytes(candidate_bytes, "big") % p
        if candidate in (0, 1, p - 1):
            seed += 1
            continue
        generator = pow(candidate, 2, p)
        if generator != 1 and pow(generator, q, p) == 1:
            return generator
        seed += 1