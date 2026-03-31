from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List


@dataclass(frozen=True)
class MockCiphertext:
    payload: str


class MockThresholdFHE:
    def keygen(self, pp: Any, t: int, n: int) -> tuple[str, List[str]]:
        return "mock_public_key", [f"sk_share_{index + 1}" for index in range(n)]

    def encrypt(self, pk: Any, value: Any) -> MockCiphertext:
        return MockCiphertext(payload=f"enc(pk={pk},value={value})")

    def evaluate(self, circuit: str, inputs: list[Any]) -> MockCiphertext:
        return MockCiphertext(payload=f"eval(circuit={circuit},inputs={inputs})")

    def decrypt_share(self, sk_share: Any, ciphertext: MockCiphertext) -> str:
        return f"partial_decryption(sk={sk_share},ct={ciphertext.payload})"

    def decrypt(self, shares: list[str]) -> str:
        return f"decrypted_from({len(shares)}_shares)"