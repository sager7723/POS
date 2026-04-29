from __future__ import annotations

import ctypes
import json
import os
from typing import Any, Dict, Sequence

from pos.models.stage2 import DistributedKeyGenerationResult

from .api import Ciphertext, CiphertextVector, GeneratedThresholdKeyMaterial, ThresholdFHEContext


class _NativeThfheBridge:
    """
    对原生 TRLWE/TFHE 门限后端的 ctypes 封装。

    约定本地动态库导出以下符号（全部返回 UTF-8 JSON 字符串）：
    - thfhe_setup
    - thfhe_distributed_keygen
    - thfhe_encrypt_scalar
    - thfhe_homomorphic_add
    - thfhe_homomorphic_sum
    - thfhe_scale_ciphertext
    - thfhe_prefix_sum
    - thfhe_eval_compare
    - thfhe_eval_locate
    - thfhe_eval_select
    - thfhe_partial_decrypt
    - thfhe_final_decrypt
    - thfhe_free_cstring
    """

    def __init__(self) -> None:
        lib_path = os.getenv("POS_THFHE_LIB_PATH", "").strip()
        if not lib_path:
            raise RuntimeError(
                "POS_THFHE_LIB_PATH is not set. "
                "To run backend='thfhe', compile and provide the native TRLWE/TFHE backend shared library."
            )
        self._lib = ctypes.CDLL(lib_path)
        self._free = getattr(self._lib, "thfhe_free_cstring")
        self._free.argtypes = [ctypes.c_void_p]
        self._free.restype = None

    def _call_json(self, func_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        func = getattr(self._lib, func_name)
        func.argtypes = [ctypes.c_char_p]
        func.restype = ctypes.c_void_p

        raw_payload = json.dumps(payload, sort_keys=True).encode("utf-8")
        ptr = func(raw_payload)
        if not ptr:
            raise RuntimeError(f"{func_name} returned null pointer")

        try:
            raw_response = ctypes.cast(ptr, ctypes.c_char_p).value
            if raw_response is None:
                raise RuntimeError(f"{func_name} returned empty response")
            return json.loads(raw_response.decode("utf-8"))
        finally:
            self._free(ptr)


class NativeThfheBackend:
    backend_name = "thfhe"

    def __init__(self) -> None:
        self._bridge = _NativeThfheBridge()
        self._participant_ids: tuple[str, ...] = tuple()
        self._loaded_key_result: DistributedKeyGenerationResult | None = None
        self._context: ThresholdFHEContext | None = None
        self._plaintext_modulus = int(os.getenv("POS_THFHE_PLAINTEXT_MODULUS", "65536"))

    @classmethod
    def build_threshold_key_material(
        cls,
        participant_ids: Sequence[str],
        threshold: int,
    ) -> GeneratedThresholdKeyMaterial:
        backend = cls()
        participant_ids = tuple(dict.fromkeys(participant_ids))
        response = backend._bridge._call_json(
            "thfhe_distributed_keygen",
            {
                "backend_name": "thfhe",
                "participant_ids": list(participant_ids),
                "threshold": threshold,
                "params": {
                    "scheme": "trlwe_thfhe",
                    "security_level": 128,
                },
            },
        )
        return GeneratedThresholdKeyMaterial(
            backend_name=response["backend_name"],
            public_key=response["public_key"],
            keyset_reference=response["keyset_reference"],
            participant_private_share_handles=dict(response["participant_private_share_handles"]),
        )

    def setup(self, params: dict[str, Any]) -> ThresholdFHEContext:
        response = self._bridge._call_json("thfhe_setup", params)
        self._context = ThresholdFHEContext(
            backend_name="thfhe",
            keyset_reference=response["keyset_reference"],
            threshold=int(response["threshold"]),
            participant_ids=tuple(response["participant_ids"]),
            params=dict(response["params"]),
        )
        return self._context

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        self._participant_ids = tuple(dict.fromkeys(participant_ids))

    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None:
        if distributed_key_result.fhe_backend_name != "thfhe":
            raise ValueError(
                f"distributed_key_result backend mismatch: expected 'thfhe', got '{distributed_key_result.fhe_backend_name}'"
            )
        self._loaded_key_result = distributed_key_result
        self._participant_ids = tuple(distributed_key_result.threshold_fhe_private_key_shares.keys())
        self._context = ThresholdFHEContext(
            backend_name="thfhe",
            keyset_reference=distributed_key_result.fhe_keyset_reference or "",
            threshold=distributed_key_result.threshold,
            participant_ids=self._participant_ids,
            params={"scheme": "trlwe_thfhe", "security_level": 128},
        )

    def get_plaintext_modulus(self) -> int:
        return self._plaintext_modulus

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str:
        return ciphertext.payload

    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext:
        if isinstance(payload, Ciphertext):
            return payload
        data = json.loads(payload)
        return Ciphertext(
            backend=str(data["backend"]),
            encoded_value=data["encoded_value"],
            metadata=dict(data["metadata"]),
        )

    def _require_context(self) -> ThresholdFHEContext:
        if self._context is None:
            raise RuntimeError(
                "ThFHE context is not loaded. Call initialize_fhe_backend(distributed_key_result=...) first."
            )
        return self._context

    def _call_ciphertext(self, func_name: str, payload: dict[str, Any]) -> Ciphertext:
        response = self._bridge._call_json(func_name, payload)
        return Ciphertext(
            backend=response["backend"],
            encoded_value=response["encoded_value"],
            metadata=dict(response["metadata"]),
        )

    def _call_ciphertext_vector(self, func_name: str, payload: dict[str, Any]) -> CiphertextVector:
        response = self._bridge._call_json(func_name, payload)
        return [
            Ciphertext(
                backend=item["backend"],
                encoded_value=item["encoded_value"],
                metadata=dict(item["metadata"]),
            )
            for item in response["ciphertexts"]
        ]

    def encrypt_scalar(self, value: int | float) -> Ciphertext:
        ctx = self._require_context()
        return self._call_ciphertext(
            "thfhe_encrypt_scalar",
            {
                "keyset_reference": ctx.keyset_reference,
                "value": value,
            },
        )

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        ctx = self._require_context()
        return self._call_ciphertext(
            "thfhe_homomorphic_add",
            {
                "keyset_reference": ctx.keyset_reference,
                "left": json.loads(left.payload),
                "right": json.loads(right.payload),
            },
        )

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        ctx = self._require_context()
        return self._call_ciphertext(
            "thfhe_homomorphic_sum",
            {
                "keyset_reference": ctx.keyset_reference,
                "ciphertexts": [json.loads(ct.payload) for ct in ciphertexts],
            },
        )

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        ctx = self._require_context()
        return self._call_ciphertext(
            "thfhe_scale_ciphertext",
            {
                "keyset_reference": ctx.keyset_reference,
                "ciphertext": json.loads(ciphertext.payload),
                "scale_ratio": scale_ratio,
            },
        )

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector:
        ctx = self._require_context()
        return self._call_ciphertext_vector(
            "thfhe_prefix_sum",
            {
                "keyset_reference": ctx.keyset_reference,
                "ciphertexts": [json.loads(ct.payload) for ct in ciphertexts],
            },
        )

    def eval_compare(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        ctx = self._require_context()
        return self._call_ciphertext_vector(
            "thfhe_eval_compare",
            {
                "keyset_reference": ctx.keyset_reference,
                "x_cipher": json.loads(x_cipher.payload),
                "y_ciphers": [json.loads(ct.payload) for ct in y_ciphers],
            },
        )

    def eval_locate(self, selector_bits: Sequence[Ciphertext]) -> CiphertextVector:
        ctx = self._require_context()
        return self._call_ciphertext_vector(
            "thfhe_eval_locate",
            {
                "keyset_reference": ctx.keyset_reference,
                "selector_bits": [json.loads(ct.payload) for ct in selector_bits],
            },
        )

    def eval_select(
        self,
        locator_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        ctx = self._require_context()
        return self._call_ciphertext(
            "thfhe_eval_select",
            {
                "keyset_reference": ctx.keyset_reference,
                "locator_bits": [json.loads(ct.payload) for ct in locator_bits],
                "value_ciphertexts": [json.loads(ct.payload) for ct in value_ciphertexts],
            },
        )

    def partial_decrypt(self, participant_id: str, ciphertext: Ciphertext) -> str:
        ctx = self._require_context()
        if self._loaded_key_result is None:
            raise RuntimeError("distributed_key_result is not loaded")
        share_handle = self._loaded_key_result.threshold_fhe_private_key_shares[participant_id].private_key_handle
        response = self._bridge._call_json(
            "thfhe_partial_decrypt",
            {
                "keyset_reference": ctx.keyset_reference,
                "participant_id": participant_id,
                "share_handle": share_handle,
                "ciphertext": json.loads(ciphertext.payload),
            },
        )
        return json.dumps(response, sort_keys=True)

    def final_decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        ctx = self._require_context()
        response = self._bridge._call_json(
            "thfhe_final_decrypt",
            {
                "keyset_reference": ctx.keyset_reference,
                "ciphertext": json.loads(ciphertext.payload),
                "shares": [json.loads(item) for item in shares],
            },
        )
        return int(response["plaintext"])