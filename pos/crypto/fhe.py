from __future__ import annotations

from dataclasses import dataclass
import json
from typing import List, Protocol, Sequence, runtime_checkable


@dataclass(frozen=True)
class Ciphertext:
    backend: str
    encoded_value: int
    metadata: dict[str, float | int | str]

    @property
    def payload(self) -> str:
        return json.dumps(
            {
                "backend": self.backend,
                "encoded_value": self.encoded_value,
                "metadata": self.metadata,
            },
            sort_keys=True,
        )


CiphertextVector = List[Ciphertext]


@runtime_checkable
class FHEBackendProtocol(Protocol):
    backend_name: str

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str: ...
    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext: ...

    def get_plaintext_modulus(self) -> int: ...

    def encrypt(self, value: int) -> Ciphertext: ...
    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext: ...
    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext: ...
    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext: ...

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector: ...
    def compare_lt_vector(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector: ...
    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext: ...

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str: ...
    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int: ...


class CompatibilityFHEBackend:
    backend_name = "compatibility"

    def __init__(self, plaintext_modulus: int = 2**31 - 1) -> None:
        self._plaintext_modulus = plaintext_modulus

    def get_plaintext_modulus(self) -> int:
        return self._plaintext_modulus

    def _normalize(self, value: int) -> int:
        return value % self._plaintext_modulus

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str:
        return json.dumps(
            {
                "backend": ciphertext.backend,
                "encoded_value": ciphertext.encoded_value,
                "metadata": ciphertext.metadata,
            },
            sort_keys=True,
        )

    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext:
        if isinstance(payload, Ciphertext):
            return payload

        if payload.startswith("enc("):
            value_str = payload.split("value=", 1)[1].rsplit(")", 1)[0]
            if value_str.startswith("stake(") and value_str.endswith(")"):
                encoded_value = int(value_str[6:-1])
            elif value_str.startswith("prf_share:0x"):
                encoded_value = int(value_str.split(":0x", 1)[1], 16)
            elif value_str.startswith("ticket_hash_suffix(") and value_str.endswith(")"):
                suffix = value_str[len("ticket_hash_suffix("):-1]
                encoded_value = int(suffix, 16)
            else:
                encoded_value = 0
            return Ciphertext(
                backend=self.backend_name,
                encoded_value=self._normalize(encoded_value),
                metadata={"legacy": 1},
            )

        data = json.loads(payload)
        return Ciphertext(
            backend=str(data["backend"]),
            encoded_value=int(data["encoded_value"]),
            metadata=dict(data["metadata"]),
        )

    def encrypt(self, value: int) -> Ciphertext:
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=self._normalize(value),
            metadata={"noise": 0.0},
        )

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=self._normalize(left.encoded_value + right.encoded_value),
            metadata={
                "noise": float(left.metadata.get("noise", 0.0)) + float(right.metadata.get("noise", 0.0))
            },
        )

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        total = self.encrypt(0)
        for ciphertext in ciphertexts:
            total = self.homomorphic_add(total, ciphertext)
        return total

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        scaled_value = int(round(ciphertext.encoded_value * scale_ratio))
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=self._normalize(scaled_value),
            metadata={
                "noise": float(ciphertext.metadata.get("noise", 0.0)),
                "scale_ratio": scale_ratio,
            },
        )

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector:
        result: CiphertextVector = []
        running = self.encrypt(0)
        for ciphertext in ciphertexts:
            running = self.homomorphic_add(running, ciphertext)
            result.append(running)
        return result

    def compare_lt_vector(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        return [
            self.encrypt(1 if x_cipher.encoded_value < y_cipher.encoded_value else 0)
            for y_cipher in y_ciphers
        ]

    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        for selector, value in zip(selector_bits, value_ciphertexts):
            if selector.encoded_value != 0:
                return value
        return value_ciphertexts[-1]

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str:
        return json.dumps(
            {
                "participant_id": participant_id,
                "backend": self.backend_name,
                "share_value": ciphertext.encoded_value,
            },
            sort_keys=True,
        )

    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        if not shares:
            raise ValueError("shares must not be empty")
        return ciphertext.encoded_value


class OpenFHEBackend:
    backend_name = "openfhe"

    def __init__(self) -> None:
        raise RuntimeError(
            "OpenFHE backend integration is not enabled yet. "
            "Current code uses the compatibility backend facade."
        )


class ConcreteBackend:
    backend_name = "concrete"

    def __init__(self) -> None:
        raise RuntimeError(
            "Concrete backend is not enabled in the current environment."
        )


class FHEThresholdFacade:
    def __init__(self, backend: FHEBackendProtocol) -> None:
        self._backend = backend

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str:
        return self._backend.serialize_ciphertext(ciphertext)

    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext:
        return self._backend.deserialize_ciphertext(payload)

    def get_plaintext_modulus(self) -> int:
        return self._backend.get_plaintext_modulus()

    def encrypt(self, value: int) -> Ciphertext:
        return self._backend.encrypt(value)

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        return self._backend.homomorphic_add(left, right)

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        return self._backend.homomorphic_sum(ciphertexts)

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        return self._backend.scale_ciphertext(ciphertext, scale_ratio)

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector:
        return self._backend.prefix_sum(ciphertexts)

    def compare_lt_vector(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        return self._backend.compare_lt_vector(x_cipher, y_ciphers)

    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        return self._backend.select_first_true(selector_bits, value_ciphertexts)

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str:
        return self._backend.decrypt_share(participant_id, ciphertext)

    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        return self._backend.decrypt(ciphertext, shares)


def initialize_fhe_backend(candidate_messages: dict[str, object] | None = None) -> FHEThresholdFacade:
    return FHEThresholdFacade(CompatibilityFHEBackend())


class MockCiphertext(Ciphertext):
    pass


class MockThresholdFHE:
    def __init__(self) -> None:
        self._facade = initialize_fhe_backend()

    def keygen(self, pp: object, t: int, n: int) -> tuple[str, List[str]]:
        return "compatibility_key_placeholder", [f"sk_share_{index + 1}" for index in range(n)]

    def encrypt(self, pk: object, value: object) -> MockCiphertext:
        if isinstance(value, int):
            encoded_value = value
        elif isinstance(value, str) and value.startswith("prf_share:0x"):
            encoded_value = int(value.split(":0x", 1)[1], 16)
        elif isinstance(value, str) and value.startswith("ticket_hash_suffix(") and value.endswith(")"):
            encoded_value = int(value[len("ticket_hash_suffix("):-1], 16)
        elif isinstance(value, str) and value.startswith("stake(") and value.endswith(")"):
            encoded_value = int(value[6:-1])
        else:
            encoded_value = 0

        return MockCiphertext(
            backend="compatibility",
            encoded_value=encoded_value,
            metadata={"pk": str(pk)},
        )

    def evaluate(self, circuit: str, inputs: list[object]) -> MockCiphertext:
        return MockCiphertext(
            backend="compatibility",
            encoded_value=0,
            metadata={"circuit": circuit, "input_count": len(inputs)},
        )

    def decrypt_share(self, sk_share: object, ciphertext: MockCiphertext) -> str:
        return json.dumps(
            {
                "sk_share": str(sk_share),
                "share_value": ciphertext.encoded_value,
            },
            sort_keys=True,
        )

    def decrypt(self, shares: list[str]) -> str:
        return f"compatibility_decrypt_from_{len(shares)}_shares"