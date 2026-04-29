from __future__ import annotations

from typing import Sequence

from .api import Ciphertext, CiphertextVector, GeneratedThresholdKeyMaterial, ThresholdFHEContext


class OpenFHEReplacementBackend:
    """
    这条路径被显式隔离出来，不再和 fhe.py 混写。
    当前这一步的目标是切到原生 ThFHE/TRLWE 家族实现，因此这里不再充当默认后端。
    """

    backend_name = "openfhe_replacement"

    @classmethod
    def build_threshold_key_material(
        cls,
        participant_ids: Sequence[str],
        threshold: int,
    ) -> GeneratedThresholdKeyMaterial:
        raise RuntimeError(
            "backend='openfhe_replacement' is intentionally isolated from the final TRLWE/ThFHE build. "
            "For the exact patent-aligned route, use backend='thfhe'."
        )

    def setup(self, params: dict) -> ThresholdFHEContext:
        raise RuntimeError("openfhe_replacement is not the final backend in this build")

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str:
        return ciphertext.payload

    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext:
        if isinstance(payload, Ciphertext):
            return payload
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def get_plaintext_modulus(self) -> int:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def load_distributed_key_result(self, distributed_key_result) -> None:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def encrypt_scalar(self, value: int | float) -> Ciphertext:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def eval_compare(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def eval_locate(self, selector_bits: Sequence[Ciphertext]) -> CiphertextVector:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def eval_select(self, locator_bits: Sequence[Ciphertext], value_ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def partial_decrypt(self, participant_id: str, ciphertext: Ciphertext) -> str:
        raise RuntimeError("openfhe_replacement is not enabled in this build")

    def final_decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        raise RuntimeError("openfhe_replacement is not enabled in this build")