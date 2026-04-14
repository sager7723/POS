from __future__ import annotations

from dataclasses import dataclass
import math
import secrets
from typing import Any, Sequence


DEFAULT_SHAMIR_PRIME = (1 << 521) - 1


@dataclass(frozen=True)
class ShamirShare:
    index: int
    values: tuple[int, ...]
    threshold: int
    prime: int
    encoded_length: int
    chunk_lengths: tuple[int, ...]


class ShamirSecretSharing:
    """
    真实 Shamir Secret Sharing。

    - 在素域 F_p 上为每个分块独立采样多项式；
    - 使用相同的 x 坐标集合形成一组 share；
    - 支持 recover_secret 与指数上的恢复。
    """

    def __init__(self, default_prime: int = DEFAULT_SHAMIR_PRIME) -> None:
        self._default_prime = default_prime

    @staticmethod
    def _chunk_size(prime: int) -> int:
        return (prime.bit_length() - 1) // 8

    @staticmethod
    def _encode_secret(secret: Any) -> bytes:
        if isinstance(secret, int):
            if secret < 0:
                raise ValueError("secret int must be non-negative")
            body = b"I" + secret.to_bytes(max(1, (secret.bit_length() + 7) // 8), "big")
            return len(body).to_bytes(4, "big") + body
        if isinstance(secret, bytes):
            body = b"B" + secret
            return len(body).to_bytes(4, "big") + body
        if isinstance(secret, str):
            body = b"S" + secret.encode("utf-8")
            return len(body).to_bytes(4, "big") + body
        body = b"R" + repr(secret).encode("utf-8")
        return len(body).to_bytes(4, "big") + body

    @staticmethod
    def _decode_secret(encoded: bytes) -> Any:
        if len(encoded) < 5:
            raise ValueError("encoded secret too short")
        declared_length = int.from_bytes(encoded[:4], "big")
        payload = encoded[4:4 + declared_length]
        if len(payload) != declared_length:
            raise ValueError("encoded secret truncated")
        kind = payload[:1]
        body = payload[1:]
        if kind == b"I":
            return int.from_bytes(body, "big") if body else 0
        if kind == b"B":
            return body
        if kind in (b"S", b"R"):
            return body.decode("utf-8")
        raise ValueError("unknown encoded secret kind")

    @staticmethod
    def _eval_polynomial(coefficients: Sequence[int], x: int, prime: int) -> int:
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * x + coefficient) % prime
        return result

    @staticmethod
    def _lagrange_coefficient_at_zero(x_i: int, xs: Sequence[int], prime: int) -> int:
        numerator = 1
        denominator = 1
        for x_j in xs:
            if x_j == x_i:
                continue
            numerator = (numerator * (-x_j % prime)) % prime
            denominator = (denominator * (x_i - x_j)) % prime
        return numerator * pow(denominator % prime, -1, prime) % prime

    def share_secret(
        self,
        secret: Any,
        n: int,
        threshold: int | None = None,
        prime: int | None = None,
    ) -> list[ShamirShare]:
        if n < 2:
            raise ValueError("n must be at least 2")
        field_prime = prime or self._default_prime
        effective_threshold = threshold or max(2, math.ceil((2 * n) / 3))
        if effective_threshold < 2 or effective_threshold > n:
            raise ValueError("threshold must satisfy 2 <= threshold <= n")

        encoded = self._encode_secret(secret)
        chunk_size = self._chunk_size(field_prime)
        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]
        chunk_lengths = tuple(len(chunk) for chunk in chunks)
        secrets_as_ints = [int.from_bytes(chunk, "big") for chunk in chunks]
        if any(secret_int >= field_prime for secret_int in secrets_as_ints):
            raise ValueError("configured prime is too small for encoded secret chunks")

        y_matrix: list[list[int]] = [[0 for _ in secrets_as_ints] for _ in range(n)]
        for chunk_index, secret_int in enumerate(secrets_as_ints):
            coefficients = [secret_int] + [secrets.randbelow(field_prime) for _ in range(effective_threshold - 1)]
            for share_index in range(1, n + 1):
                y_matrix[share_index - 1][chunk_index] = self._eval_polynomial(coefficients, share_index, field_prime)

        return [
            ShamirShare(
                index=share_index,
                values=tuple(y_matrix[share_index - 1]),
                threshold=effective_threshold,
                prime=field_prime,
                encoded_length=len(encoded),
                chunk_lengths=chunk_lengths,
            )
            for share_index in range(1, n + 1)
        ]

    def recover_secret(self, shares: Sequence[ShamirShare]) -> Any:
        if not shares:
            raise ValueError("shares must not be empty")

        first = shares[0]
        if len(shares) < first.threshold:
            raise ValueError("insufficient shares to recover secret")

        selected = list(shares[:first.threshold])
        xs = [share.index for share in selected]
        chunk_count = len(first.values)
        for share in selected:
            if (
                share.threshold != first.threshold
                or share.prime != first.prime
                or share.encoded_length != first.encoded_length
                or len(share.values) != chunk_count
                or share.chunk_lengths != first.chunk_lengths
            ):
                raise ValueError("incompatible shares")

        recovered_chunks: list[int] = []
        for chunk_index in range(chunk_count):
            value = 0
            for share in selected:
                coefficient = self._lagrange_coefficient_at_zero(share.index, xs, first.prime)
                value = (value + share.values[chunk_index] * coefficient) % first.prime
            recovered_chunks.append(value)

        chunk_size = self._chunk_size(first.prime)
        reconstructed = b"".join(
            chunk.to_bytes(chunk_size, "big")[-first.chunk_lengths[index]:]
            for index, chunk in enumerate(recovered_chunks)
        )[:first.encoded_length]
        return self._decode_secret(reconstructed)

    def recover_secret_in_exponent(
        self,
        shares: Sequence[ShamirShare],
        generator: int | None = None,
        modulus: int | None = None,
    ) -> Any:
        secret = self.recover_secret(shares)
        if generator is None or modulus is None:
            return secret
        if not isinstance(secret, int):
            raise ValueError("exponent recovery requires an integer secret")
        return pow(generator, secret, modulus)


MockSecretSharing = ShamirSecretSharing