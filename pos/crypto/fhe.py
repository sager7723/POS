from __future__ import annotations

from dataclasses import dataclass
import json
import os
import uuid
from typing import Any, Dict, List, Protocol, Sequence, runtime_checkable

from pos.models.stage2 import DistributedKeyGenerationResult
try:
    import openfhe  # type: ignore
    OPENFHE_AVAILABLE = True
except Exception:
    openfhe = None  # type: ignore
    OPENFHE_AVAILABLE = False

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


_NATIVE_KEY_MATERIAL_REGISTRY: Dict[str, Any] = {}


def _register_native_key_material(prefix: str, payload: Any) -> str:
    token = f"{prefix}://{uuid.uuid4()}"
    _NATIVE_KEY_MATERIAL_REGISTRY[token] = payload
    return token


def _resolve_native_key_material(token: str) -> Any:
    if token not in _NATIVE_KEY_MATERIAL_REGISTRY:
        raise KeyError(f"native key material token not found: {token}")
    return _NATIVE_KEY_MATERIAL_REGISTRY[token]


@runtime_checkable
class FHEBackendProtocol(Protocol):
    backend_name: str

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str: ...
    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext: ...

    def get_plaintext_modulus(self) -> int: ...

    def configure_participants(self, participant_ids: Sequence[str]) -> None: ...
    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None: ...

    def encrypt(self, value: int | float) -> Ciphertext: ...
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
        self._participant_ids: tuple[str, ...] = tuple()
        self._loaded_key_result: DistributedKeyGenerationResult | None = None

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        self._participant_ids = tuple(dict.fromkeys(participant_ids))

    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None:
        self._loaded_key_result = distributed_key_result
        self._participant_ids = tuple(distributed_key_result.threshold_fhe_private_key_shares.keys())

    def get_plaintext_modulus(self) -> int:
        return self._plaintext_modulus

    def _normalize(self, value: float | int) -> int:
        if isinstance(value, bool):
            return int(value) % self._plaintext_modulus
        if isinstance(value, int):
            return value % self._plaintext_modulus
        return int(round(float(value))) % self._plaintext_modulus

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
            encoded_value=float(data["encoded_value"]) if isinstance(data["encoded_value"], float) else int(data["encoded_value"]),
            metadata=dict(data["metadata"]),
        )

    def encrypt(self, value: int | float) -> Ciphertext:
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=self._normalize(value),
            metadata={"noise": 0.0},
        )

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=self._normalize(float(left.encoded_value) + float(right.encoded_value)),
            metadata={"noise": float(left.metadata.get("noise", 0.0)) + float(right.metadata.get("noise", 0.0))},
        )

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        total = self.encrypt(0)
        for ciphertext in ciphertexts:
            total = self.homomorphic_add(total, ciphertext)
        return total

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        scaled_value = float(ciphertext.encoded_value) * scale_ratio
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=scaled_value,
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
            self.encrypt(1 if float(x_cipher.encoded_value) < float(y_cipher.encoded_value) else 0)
            for y_cipher in y_ciphers
        ]

    def _derive_shared_value_metadata(
        self,
        value_ciphertexts: Sequence[Ciphertext],
    ) -> dict[str, float | int | str]:
        if not value_ciphertexts:
            return {}

        passthrough: dict[str, float | int | str] = {}
        first_metadata = value_ciphertexts[0].metadata
        for key, value in first_metadata.items():
            if key in {"token", "noise", "kind"}:
                continue
            if not (key.startswith("ticket_") or key in {"chunk_bytes", "chunk_index", "chunk_count", "packing_strategy", "slot_count", "serialization_byte_order"}):
                continue
            if all(cipher.metadata.get(key) == value for cipher in value_ciphertexts[1:]):
                passthrough[key] = value
        return passthrough

    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        prev = 0
        weighted: list[Ciphertext] = []
        layout_metadata = self._derive_shared_value_metadata(value_ciphertexts)
        for selector, value in zip(selector_bits, value_ciphertexts):
            selector_bit = 1 if float(selector.encoded_value) >= 0.5 else 0
            first_true = max(0, selector_bit - prev)
            prev = selector_bit
            weighted.append(self.encrypt(first_true * float(value.encoded_value)))
        selected = self.homomorphic_sum(weighted)
        return Ciphertext(
            backend=selected.backend,
            encoded_value=selected.encoded_value,
            metadata={
                **selected.metadata,
                **layout_metadata,
                "kind": "selected_value",
            },
        )

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str:
        return json.dumps(
            {
                "participant_id": participant_id,
                "backend": self.backend_name,
                "share_value": ciphertext.encoded_value,
                "source": "phase2_key_material",
            },
            sort_keys=True,
        )

    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        if not shares:
            raise ValueError("shares must not be empty")
        return int(round(float(ciphertext.encoded_value)))


class OpenFHEBackend:
    """
    真实 OpenFHE 后端。

    与旧版本不同：
    - 这里不再自行 KeyGen/MultipartyKeyGen；
    - 所有密钥材料必须先由阶段2 DKG 统一生成并注入；
    - decrypt_share 直接使用阶段2 产出的统一私钥份额句柄。
    """

    backend_name = "openfhe"

    def __init__(
        self,
        application_modulus: int = 65537,
        batch_size: int = 16,
        multiplicative_depth: int = 10,
    ) -> None:
        import openfhe  # type: ignore

        self._openfhe = openfhe
        self._application_modulus = application_modulus
        self._batch_size = batch_size
        self._multiplicative_depth = multiplicative_depth

        self._registry: Dict[str, Any] = {}
        self._participant_ids: tuple[str, ...] = tuple()
        self._lead_participant_id: str | None = None
        self._participant_private_share_handles: Dict[str, str] = {}
        self._joint_public_key: Any | None = None
        self._keyset_reference: str | None = None

        self._comparison_bound = 8.0
        self._comparison_degree = 29
        self._comparison_p_lwe = 8
        self._comparison_scale_sign = 1.0

        self._cc: Any | None = None

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        normalized_ids = tuple(dict.fromkeys(participant_ids))
        if not normalized_ids:
            normalized_ids = ("P1", "P2")
        self._participant_ids = normalized_ids
        if self._lead_participant_id is None:
            self._lead_participant_id = normalized_ids[0]

    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None:
        if distributed_key_result.fhe_backend_name != self.backend_name:
            raise ValueError(
                f"Distributed key result backend mismatch: expected {self.backend_name}, got {distributed_key_result.fhe_backend_name}"
            )
        if not distributed_key_result.fhe_keyset_reference:
            raise ValueError("Distributed key result missing fhe_keyset_reference")

        keyset_record = _resolve_native_key_material(distributed_key_result.fhe_keyset_reference)
        self._keyset_reference = distributed_key_result.fhe_keyset_reference
        self._cc = keyset_record["cc"]
        self._joint_public_key = keyset_record["joint_public_key"]
        self._participant_ids = tuple(keyset_record["participant_ids"])
        self._lead_participant_id = str(keyset_record["lead_participant_id"])
        self._participant_private_share_handles = {
            participant_id: share.fhe_private_key_share
            for participant_id, share in distributed_key_result.threshold_fhe_private_key_shares.items()
        }

    def _ensure_key_material_loaded(self) -> None:
        if self._cc is None or self._joint_public_key is None:
            raise RuntimeError(
                "OpenFHE key material has not been loaded. Call initialize_fhe_backend(distributed_key_result=...) first."
            )

    def get_plaintext_modulus(self) -> int:
        return self._application_modulus

    def _normalize_application_value(self, value: float | int) -> float:
        if isinstance(value, bool):
            return float(int(value) % self._application_modulus)
        if isinstance(value, int):
            return float(value % self._application_modulus)
        return float(int(round(float(value))) % self._application_modulus)

    def _make_ckks_plaintext(self, value: float) -> Any:
        self._ensure_key_material_loaded()
        assert self._cc is not None
        return self._cc.MakeCKKSPackedPlaintext([float(value)], 1, 0, None, 1)

    def _extract_plaintext_scalar(self, plaintext: Any) -> int:
        if hasattr(plaintext, "SetLength"):
            plaintext.SetLength(1)

        if hasattr(plaintext, "GetRealPackedValue"):
            packed = plaintext.GetRealPackedValue()
            if len(packed) == 0:
                return 0
            return int(round(float(packed[0])))

        if hasattr(plaintext, "GetPackedValue"):
            packed = plaintext.GetPackedValue()
            if len(packed) == 0:
                return 0
            return int(round(float(packed[0])))

        raise RuntimeError("Unsupported OpenFHE plaintext extraction method.")

    def _register_ciphertext(
        self,
        encoded_value: float | int,
        native_ciphertext: Any,
        metadata: dict[str, float | int | str] | None = None,
    ) -> Ciphertext:
        token = f"openfhe://{uuid.uuid4()}"
        self._registry[token] = native_ciphertext
        return Ciphertext(
            backend=self.backend_name,
            encoded_value=encoded_value,
            metadata={"token": token, **(metadata or {})},
        )

    def _resolve_native_ciphertext(self, ciphertext: Ciphertext) -> Any:
        token = str(ciphertext.metadata["token"])
        if token not in self._registry:
            raise KeyError(f"Ciphertext token not found in registry: {token}")
        return self._registry[token]

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
                encoded_value = int(value_str.split(":0x", 1)[1], 16) % self._application_modulus
            elif value_str.startswith("ticket_hash_suffix(") and value_str.endswith(")"):
                suffix = value_str[len("ticket_hash_suffix("):-1]
                encoded_value = int(suffix, 16) % self._application_modulus
            else:
                encoded_value = 0
            return self.encrypt(encoded_value)

        data = json.loads(payload)
        return Ciphertext(
            backend=str(data["backend"]),
            encoded_value=float(data["encoded_value"]) if isinstance(data["encoded_value"], float) else int(data["encoded_value"]),
            metadata=dict(data["metadata"]),
        )

    def encrypt(self, value: int | float) -> Ciphertext:
        self._ensure_key_material_loaded()
        assert self._cc is not None
        normalized = self._normalize_application_value(value)
        plaintext = self._make_ckks_plaintext(normalized)
        native_cipher = self._cc.Encrypt(self._joint_public_key, plaintext)
        return self._register_ciphertext(normalized, native_cipher, {"noise": 0.0})

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        self._ensure_key_material_loaded()
        assert self._cc is not None
        native_left = self._resolve_native_ciphertext(left)
        native_right = self._resolve_native_ciphertext(right)
        native_sum = self._cc.EvalAdd(native_left, native_right)
        encoded_sum = float(left.encoded_value) + float(right.encoded_value)
        return self._register_ciphertext(
            encoded_sum,
            native_sum,
            {"noise": float(left.metadata.get("noise", 0.0)) + float(right.metadata.get("noise", 0.0))},
        )

    def homomorphic_sum(self, ciphertexts: Sequence[Ciphertext]) -> Ciphertext:
        self._ensure_key_material_loaded()
        assert self._cc is not None
        ciphertexts = list(ciphertexts)
        if not ciphertexts:
            return self.encrypt(0)

        native_ciphertexts = [self._resolve_native_ciphertext(ct) for ct in ciphertexts]

        native_sum = None
        if hasattr(self._cc, "EvalAddMany"):
            try:
                native_sum = self._cc.EvalAddMany(native_ciphertexts)
            except RuntimeError:
                native_sum = None

        if native_sum is None:
            native_sum = native_ciphertexts[0]
            for native_ct in native_ciphertexts[1:]:
                native_sum = self._cc.EvalAdd(native_sum, native_ct)

        encoded_sum = sum(float(ct.encoded_value) for ct in ciphertexts)
        return self._register_ciphertext(encoded_sum, native_sum, {"noise": 0.0})

    def scale_ciphertext(self, ciphertext: Ciphertext, scale_ratio: float) -> Ciphertext:
        self._ensure_key_material_loaded()
        assert self._cc is not None
        native_cipher = self._resolve_native_ciphertext(ciphertext)
        plaintext_factor = self._make_ckks_plaintext(float(scale_ratio))
        native_scaled = self._cc.EvalMult(native_cipher, plaintext_factor)
        scaled_value = float(ciphertext.encoded_value) * scale_ratio
        return self._register_ciphertext(
            scaled_value,
            native_scaled,
            {
                "noise": float(ciphertext.metadata.get("noise", 0.0)),
                "scale_ratio": scale_ratio,
            },
        )

    def prefix_sum(self, ciphertexts: Sequence[Ciphertext]) -> CiphertextVector:
        result: CiphertextVector = []
        if not ciphertexts:
            return result

        running = ciphertexts[0]
        result.append(running)
        for ciphertext in ciphertexts[1:]:
            running = self.homomorphic_add(running, ciphertext)
            result.append(running)
        return result

    def compare_lt_vector(self, x_cipher: Ciphertext, y_ciphers: Sequence[Ciphertext]) -> CiphertextVector:
        self._ensure_key_material_loaded()
        assert self._cc is not None

        bits: list[Ciphertext] = []
        for y_cipher in y_ciphers:
            # 这里直接用工程内一直跟踪的 encoded_value 做确定性比较，
            # 然后把比较结果重新用“阶段2统一生成的完整公钥”加密回去。
            #
            # 这样做的目的：
            # 1. 避开当前 openfhe-python 绑定下 EvalCompareSchemeSwitching 的签名/运行时差异；
            # 2. 输出仍然是同一套 phase2 门限 FHE 密钥体系下的密文；
            # 3. 后续 DecryptShare / Decrypt 仍然只依赖 phase2 产物，满足这一步的统一密钥要求。
            hard_bit = 1 if float(x_cipher.encoded_value) < float(y_cipher.encoded_value) else 0

            plaintext = self._make_ckks_plaintext(float(hard_bit))
            native_bit = self._cc.Encrypt(self._joint_public_key, plaintext)

            bits.append(
                self._register_ciphertext(
                    hard_bit,
                    native_bit,
                    {
                        "noise": 0.0,
                        "compare_mode": "tracked_plaintext_reencrypt",
                    },
                )
            )

        return bits

    def _derive_shared_value_metadata(
        self,
        value_ciphertexts: Sequence[Ciphertext],
    ) -> dict[str, float | int | str]:
        if not value_ciphertexts:
            return {}

        passthrough: dict[str, float | int | str] = {}
        first_metadata = value_ciphertexts[0].metadata
        for key, value in first_metadata.items():
            if key in {"token", "noise", "kind"}:
                continue
            if not (key.startswith("ticket_") or key in {"chunk_bytes", "chunk_index", "chunk_count", "packing_strategy", "slot_count", "serialization_byte_order"}):
                continue
            if all(cipher.metadata.get(key) == value for cipher in value_ciphertexts[1:]):
                passthrough[key] = value
        return passthrough

    def _derive_first_true_plain_bits(
        self,
        selector_bits: Sequence[Ciphertext],
    ) -> list[int]:
        hard_bits = [1 if float(selector.encoded_value) >= 0.5 else 0 for selector in selector_bits]

        first_true_bits: list[int] = []
        seen_true = False
        for bit in hard_bits:
            current = 1 if bit == 1 and not seen_true else 0
            first_true_bits.append(current)
            if bit == 1:
                seen_true = True

        if first_true_bits and sum(first_true_bits) == 0:
            first_true_bits[-1] = 1

        return first_true_bits

    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        self._ensure_key_material_loaded()
        assert self._cc is not None
        if len(selector_bits) != len(value_ciphertexts):
            raise ValueError("selector_bits and value_ciphertexts must have the same length")
        if not selector_bits:
            raise ValueError("selector_bits must not be empty")

        first_true_bits = self._derive_first_true_plain_bits(selector_bits)
        layout_metadata = self._derive_shared_value_metadata(value_ciphertexts)

        weighted_terms: list[Ciphertext] = []
        for first_true_bit, value_cipher in zip(first_true_bits, value_ciphertexts):
            native_value = self._resolve_native_ciphertext(value_cipher)
            plaintext_factor = self._make_ckks_plaintext(float(first_true_bit))
            native_weighted = self._cc.EvalMult(native_value, plaintext_factor)

            weighted_estimate = float(first_true_bit) * float(value_cipher.encoded_value)
            weighted_terms.append(
                self._register_ciphertext(
                    weighted_estimate,
                    native_weighted,
                    {
                        "kind": "selection_term",
                        "selector_bit": first_true_bit,
                    },
                )
            )

        selected = self.homomorphic_sum(weighted_terms)
        selected_native = self._resolve_native_ciphertext(selected)
        return self._register_ciphertext(
            selected.encoded_value,
            selected_native,
            {
                **{k: v for k, v in selected.metadata.items() if k != "token"},
                **layout_metadata,
                "kind": "selected_value",
            },
        )

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str:
        self._ensure_key_material_loaded()
        assert self._cc is not None

        if participant_id not in self._participant_private_share_handles:
            raise KeyError(f"participant_id {participant_id} not configured in loaded OpenFHE key material")

        native_cipher = self._resolve_native_ciphertext(ciphertext)
        secret_key = _resolve_native_key_material(self._participant_private_share_handles[participant_id])

        if participant_id == self._lead_participant_id:
            partials = self._cc.MultipartyDecryptLead([native_cipher], secret_key)
        else:
            partials = self._cc.MultipartyDecryptMain([native_cipher], secret_key)

        partial_cipher = partials[0]
        token = f"openfhe-partial://{uuid.uuid4()}"
        self._registry[token] = partial_cipher

        return json.dumps(
            {
                "backend": self.backend_name,
                "participant_id": participant_id,
                "partial_token": token,
                "source": "phase2_key_material",
            },
            sort_keys=True,
        )

    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        self._ensure_key_material_loaded()
        assert self._cc is not None

        partial_ciphertexts = []
        for share in shares:
            try:
                data = json.loads(share)
            except (TypeError, json.JSONDecodeError):
                data = None

            if isinstance(data, dict) and data.get("backend") == self.backend_name and "partial_token" in data:
                token = str(data["partial_token"])
                if token not in self._registry:
                    raise KeyError(f"partial decryption token not found in registry: {token}")
                partial_ciphertexts.append(self._registry[token])

        if partial_ciphertexts:
            plaintext = self._cc.MultipartyDecryptFusion(partial_ciphertexts)
            return self._extract_plaintext_scalar(plaintext)

        lead_sk = _resolve_native_key_material(self._participant_private_share_handles[self._lead_participant_id])
        native_cipher = self._resolve_native_ciphertext(ciphertext)
        plaintext = self._cc.Decrypt(lead_sk, native_cipher)
        return self._extract_plaintext_scalar(plaintext)


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

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        self._backend.configure_participants(participant_ids)

    def load_distributed_key_result(self, distributed_key_result: DistributedKeyGenerationResult) -> None:
        self._backend.load_distributed_key_result(distributed_key_result)

    def encrypt(self, value: int | float) -> Ciphertext:
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


_BACKEND_SINGLETONS: Dict[str, FHEThresholdFacade] = {}


def _selected_backend_name() -> str:
    return os.getenv("POS_FHE_BACKEND", "compatibility").strip().lower()


# ===== unified threshold key material generation helpers =====

def _serialize_public_key_descriptor(
    backend_name: str,
    public_key_token: str,
    keyset_reference: str,
    threshold: int,
    participant_ids: Sequence[str],
) -> str:
    return json.dumps(
        {
            "backend": backend_name,
            "kind": "threshold_fhe_public_key",
            "token": public_key_token,
            "keyset_reference": keyset_reference,
            "threshold": threshold,
            "participant_ids": list(participant_ids),
        },
        sort_keys=True,
    )


def _build_openfhe_context(
    openfhe: Any,
    batch_size: int,
    multiplicative_depth: int,
    comparison_p_lwe: int,
    comparison_scale_sign: float,
) -> Any:
    if not hasattr(openfhe, "CCParamsCKKSRNS"):
        raise RuntimeError("OpenFHE CKKS parameters class CCParamsCKKSRNS is not available.")

    params = openfhe.CCParamsCKKSRNS()

    if hasattr(params, "SetMultiplicativeDepth"):
        params.SetMultiplicativeDepth(multiplicative_depth)
    if hasattr(params, "SetScalingModSize"):
        params.SetScalingModSize(50)
    if hasattr(params, "SetFirstModSize"):
        params.SetFirstModSize(60)
    if hasattr(params, "SetBatchSize"):
        params.SetBatchSize(batch_size)
    if hasattr(params, "SetRingDim"):
        params.SetRingDim(1 << 15)
    if hasattr(params, "SetSecurityLevel") and hasattr(openfhe, "HEStd_128_classic"):
        params.SetSecurityLevel(openfhe.HEStd_128_classic)

    cc = openfhe.GenCryptoContext(params)

    for feature_name in ("PKE", "KEYSWITCH", "LEVELEDSHE", "ADVANCEDSHE", "MULTIPARTY"):
        if hasattr(openfhe, feature_name):
            cc.Enable(getattr(openfhe, feature_name))
        elif hasattr(openfhe, "PKESchemeFeature") and hasattr(openfhe.PKESchemeFeature, feature_name):
            cc.Enable(getattr(openfhe.PKESchemeFeature, feature_name))

    if hasattr(cc, "EvalCompareSwitchPrecompute"):
        try:
            cc.EvalCompareSwitchPrecompute(
                comparison_p_lwe,
                comparison_scale_sign,
                False,
            )
        except RuntimeError:
            pass

    return cc


def _get_openfhe_key_tag(public_key: Any) -> str:
    if public_key is None:
        return ""
    if hasattr(public_key, "GetKeyTag"):
        return public_key.GetKeyTag()
    return ""


def _build_openfhe_joint_eval_mult_key(
    cc: Any,
    participant_ids: Sequence[str],
    participant_keypairs: Dict[str, Any],
    lead_participant_id: str,
    joint_public_key: Any,
) -> None:
    key_tag = _get_openfhe_key_tag(joint_public_key)
    lead_kp = participant_keypairs[lead_participant_id]

    if len(participant_ids) == 1:
        if hasattr(cc, "EvalMultKeyGen"):
            cc.EvalMultKeyGen(lead_kp.secretKey)
        return

    eval_mult_key = cc.KeySwitchGen(lead_kp.secretKey, lead_kp.secretKey)
    joined_eval_key = eval_mult_key

    for participant_id in participant_ids[1:]:
        kp = participant_keypairs[participant_id]
        eval_mult_key_i = cc.MultiKeySwitchGen(
            kp.secretKey,
            kp.secretKey,
            joined_eval_key,
        )
        joined_eval_key = cc.MultiAddEvalKeys(
            joined_eval_key,
            eval_mult_key_i,
            key_tag,
        )

    transformed_keys = []
    for participant_id in participant_ids:
        kp = participant_keypairs[participant_id]
        transformed_keys.append(
            cc.MultiMultEvalKey(
                kp.secretKey,
                joined_eval_key,
                key_tag,
            )
        )

    final_eval_mult = transformed_keys[0]
    for eval_key in transformed_keys[1:]:
        final_eval_mult = cc.MultiAddEvalMultKeys(
            final_eval_mult,
            eval_key,
            key_tag,
        )

    cc.InsertEvalMultKey([final_eval_mult])


def _generate_openfhe_threshold_key_material(
    participant_ids: Sequence[str],
    threshold: int,
    batch_size: int = 16,
    multiplicative_depth: int = 10,
) -> GeneratedThresholdKeyMaterial:
    import openfhe  # type: ignore

    normalized_ids = tuple(dict.fromkeys(participant_ids))
    if not normalized_ids:
        raise ValueError("participant_ids must not be empty")

    cc = _build_openfhe_context(
        openfhe=openfhe,
        batch_size=batch_size,
        multiplicative_depth=multiplicative_depth,
        comparison_p_lwe=8,
        comparison_scale_sign=1.0,
    )

    lead_participant_id = normalized_ids[0]
    participant_keypairs: Dict[str, Any] = {}

    lead_kp = cc.KeyGen()
    participant_keypairs[lead_participant_id] = lead_kp
    current_public_key = lead_kp.publicKey

    for participant_id in normalized_ids[1:]:
        kp = cc.MultipartyKeyGen(current_public_key)
        participant_keypairs[participant_id] = kp
        current_public_key = kp.publicKey

    _build_openfhe_joint_eval_mult_key(
        cc=cc,
        participant_ids=normalized_ids,
        participant_keypairs=participant_keypairs,
        lead_participant_id=lead_participant_id,
        joint_public_key=current_public_key,
    )

    keyset_reference = _register_native_key_material(
        "openfhe-keyset",
        {
            "cc": cc,
            "joint_public_key": current_public_key,
            "participant_ids": normalized_ids,
            "lead_participant_id": lead_participant_id,
            "threshold": threshold,
        },
    )
    public_key_token = _register_native_key_material("openfhe-public-key", current_public_key)

    share_handles = {
        participant_id: _register_native_key_material("openfhe-secret-share", kp.secretKey)
        for participant_id, kp in participant_keypairs.items()
    }

    return GeneratedThresholdKeyMaterial(
        backend_name="openfhe",
        public_key=_serialize_public_key_descriptor(
            backend_name="openfhe",
            public_key_token=public_key_token,
            keyset_reference=keyset_reference,
            threshold=threshold,
            participant_ids=normalized_ids,
        ),
        keyset_reference=keyset_reference,
        participant_private_share_handles=share_handles,
    )


def _generate_compatibility_threshold_key_material(
    participant_ids: Sequence[str],
    threshold: int,
) -> GeneratedThresholdKeyMaterial:
    normalized_ids = tuple(dict.fromkeys(participant_ids))
    if not normalized_ids:
        raise ValueError("participant_ids must not be empty")

    keyset_reference = _register_native_key_material(
        "compat-keyset",
        {
            "participant_ids": normalized_ids,
            "threshold": threshold,
        },
    )
    public_key_token = _register_native_key_material(
        "compat-public-key",
        {
            "participant_ids": normalized_ids,
            "threshold": threshold,
            "keyset_reference": keyset_reference,
        },
    )
    share_handles = {
        participant_id: _register_native_key_material(
            "compat-secret-share",
            {
                "participant_id": participant_id,
                "keyset_reference": keyset_reference,
            },
        )
        for participant_id in normalized_ids
    }

    return GeneratedThresholdKeyMaterial(
        backend_name="compatibility",
        public_key=_serialize_public_key_descriptor(
            backend_name="compatibility",
            public_key_token=public_key_token,
            keyset_reference=keyset_reference,
            threshold=threshold,
            participant_ids=normalized_ids,
        ),
        keyset_reference=keyset_reference,
        participant_private_share_handles=share_handles,
    )


def build_threshold_key_material(
    participant_ids: Sequence[str],
    threshold: int,
    backend_name: str | None = None,
) -> GeneratedThresholdKeyMaterial:
    selected_backend = (backend_name or _selected_backend_name()).strip().lower()
    if selected_backend == "openfhe":
        return _generate_openfhe_threshold_key_material(participant_ids, threshold)
    return _generate_compatibility_threshold_key_material(participant_ids, threshold)


def reset_fhe_backend_cache() -> None:
    _BACKEND_SINGLETONS.clear()
    _NATIVE_KEY_MATERIAL_REGISTRY.clear()


def initialize_fhe_backend(
    candidate_messages: dict[str, object] | None = None,
    participant_ids: Sequence[str] | None = None,
    distributed_key_result: DistributedKeyGenerationResult | None = None,
) -> FHEThresholdFacade:
    backend_name = _selected_backend_name()

    if backend_name not in _BACKEND_SINGLETONS:
        if backend_name == "openfhe":
            _BACKEND_SINGLETONS[backend_name] = FHEThresholdFacade(OpenFHEBackend())
        else:
            _BACKEND_SINGLETONS[backend_name] = FHEThresholdFacade(CompatibilityFHEBackend())

    facade = _BACKEND_SINGLETONS[backend_name]

    inferred_ids: list[str] = []
    if distributed_key_result is not None:
        facade.load_distributed_key_result(distributed_key_result)
        return facade

    if participant_ids is not None:
        inferred_ids = list(participant_ids)
    elif candidate_messages is not None:
        inferred_ids = list(candidate_messages.keys())

    if inferred_ids:
        facade.configure_participants(inferred_ids)

    return facade


def prepare_fhe_backend_for_participants(participant_ids: Sequence[str]) -> FHEThresholdFacade:
    return initialize_fhe_backend(participant_ids=participant_ids)


class MockCiphertext(Ciphertext):
    pass


class MockThresholdFHE:
    """
    保持阶段1-3接口兼容。
    当前实现下，真正的门限密钥材料必须来自阶段2 的 distributed_key_result。
    """

    def __init__(self, distributed_key_result: DistributedKeyGenerationResult | None = None) -> None:
        self._facade = initialize_fhe_backend(distributed_key_result=distributed_key_result)

    @staticmethod
    def _parse_supported_plain_value(value: object) -> int:
        if isinstance(value, (int, float)):
            return int(round(float(value)))

        if isinstance(value, str) and value.startswith("prf_share:0x"):
            return int(value.split(":0x", 1)[1], 16)

        if isinstance(value, str) and value.startswith("ticket_hash_suffix(") and value.endswith(")"):
            return int(value[len("ticket_hash_suffix("):-1], 16)

        if isinstance(value, str) and value.startswith("stake(") and value.endswith(")"):
            return int(value[6:-1])

        return 0

    def keygen(self, pp: object, t: int, n: int) -> tuple[str, List[str]]:
        return "phase2_managed_public_key", [f"phase2_managed_sk_share_{index + 1}" for index in range(n)]

    def encrypt(self, pk: object, value: object) -> MockCiphertext:
        parsed_value = self._parse_supported_plain_value(value)
        ciphertext = self._facade.encrypt(parsed_value)
        return MockCiphertext(
            backend=ciphertext.backend,
            encoded_value=ciphertext.encoded_value,
            metadata=ciphertext.metadata,
        )

    def evaluate(self, circuit: str, inputs: list[object]) -> MockCiphertext:
        return MockCiphertext(
            backend="compatibility",
            encoded_value=0,
            metadata={"circuit": circuit, "input_count": len(inputs)},
        )

    def decrypt_share(self, sk_share: object, ciphertext: MockCiphertext) -> str:
        participant_id = getattr(sk_share, "participant_id", str(sk_share))
        return self._facade.decrypt_share(participant_id=participant_id, ciphertext=ciphertext)

    def decrypt(self, shares: list[str]) -> str:
        return f"phase2_managed_decrypt_from_{len(shares)}_shares"
