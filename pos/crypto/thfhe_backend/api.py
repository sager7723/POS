from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, List, Protocol, Sequence, runtime_checkable

from pos.models.stage2 import DistributedKeyGenerationResult


@dataclass(frozen=True)
class Ciphertext:
    backend: str
    encoded_value: float | int
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


@dataclass(frozen=True)
class GeneratedThresholdKeyMaterial:
    backend_name: str
    public_key: str
    keyset_reference: str
    participant_private_share_handles: Dict[str, str]


@dataclass(frozen=True)
class ThresholdFHEContext:
    backend_name: str
    keyset_reference: str
    threshold: int
    participant_ids: tuple[str, ...]
    params: dict[str, Any]


@runtime_checkable
class ThresholdFHEBackendProtocol(Protocol):
    backend_name: str

    @classmethod
    def build_threshold_key_material(
        cls,
        participant_ids: Sequence[str],
        threshold: int,
    ) -> GeneratedThresholdKeyMaterial: ...

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str: ...
    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext: ...

    def get_plaintext_modulus(self) -> int: ...

    def setup(self, params: dict[str, Any]) -> ThresholdFHEContext: ...
    def configure_participants(self, participant_ids: Sequence[str]) -> None: ...
    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None: ...

    def encrypt_scalar(self, value: int | float) -> Ciphertext: ...
    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext: ...
    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext: ...
    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext: ...
    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector: ...

    def eval_compare(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector: ...
    def eval_locate(self, selector_bits: Sequence[Ciphertext]) -> CiphertextVector: ...
    def eval_select(
        self,
        locator_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext: ...

    def partial_decrypt(self, participant_id: str, ciphertext: Ciphertext) -> str: ...
    def final_decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int: ...


class FHEThresholdFacade:
    def __init__(self, backend: ThresholdFHEBackendProtocol) -> None:
        self._backend = backend

    @property
    def backend_name(self) -> str:
        return self._backend.backend_name

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str:
        return self._backend.serialize_ciphertext(ciphertext)

    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext:
        return self._backend.deserialize_ciphertext(payload)

    def get_plaintext_modulus(self) -> int:
        return self._backend.get_plaintext_modulus()

    def setup(self, params: dict[str, Any]) -> ThresholdFHEContext:
        return self._backend.setup(params)

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        self._backend.configure_participants(participant_ids)

    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None:
        self._backend.load_distributed_key_result(distributed_key_result)

    def encrypt_scalar(self, value: int | float) -> Ciphertext:
        return self._backend.encrypt_scalar(value)

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        return self._backend.homomorphic_add(left, right)

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        return self._backend.homomorphic_sum(ciphertexts)

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        return self._backend.scale_ciphertext(ciphertext, scale_ratio)

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector:
        return self._backend.prefix_sum(ciphertexts)

    def eval_compare(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        return self._backend.eval_compare(x_cipher, y_ciphers)

    def eval_locate(self, selector_bits: Sequence[Ciphertext]) -> CiphertextVector:
        return self._backend.eval_locate(selector_bits)

    def eval_select(
        self,
        locator_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        return self._backend.eval_select(locator_bits, value_ciphertexts)

    def partial_decrypt(self, participant_id: str, ciphertext: Ciphertext) -> str:
        return self._backend.partial_decrypt(participant_id, ciphertext)

    def final_decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        return self._backend.final_decrypt(ciphertext, shares)

    # ===== 向现有协议层保留兼容别名，避免 election/reveal 大改 =====

    def encrypt(self, value: int | float) -> Ciphertext:
        return self.encrypt_scalar(value)

    def compare_lt_vector(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        return self.eval_compare(x_cipher, y_ciphers)

    def locate_first_true(self, selector_bits: Sequence[Ciphertext]) -> CiphertextVector:
        return self.eval_locate(selector_bits)

    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        locator_bits = self.eval_locate(selector_bits)
        return self.eval_select(locator_bits, value_ciphertexts)

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str:
        return self.partial_decrypt(participant_id, ciphertext)

    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        return self.final_decrypt(ciphertext, shares)