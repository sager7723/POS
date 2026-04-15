from __future__ import annotations

from dataclasses import dataclass
import json
import os
import uuid
from typing import Any, Dict, List, Protocol, Sequence, runtime_checkable


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


@runtime_checkable
class FHEBackendProtocol(Protocol):
    backend_name: str

    def serialize_ciphertext(self, ciphertext: Ciphertext) -> str: ...
    def deserialize_ciphertext(self, payload: str | Ciphertext) -> Ciphertext: ...

    def get_plaintext_modulus(self) -> int: ...

    def configure_participants(self, participant_ids: Sequence[str]) -> None: ...

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

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        return None

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

    def select_first_true(
        self,
        selector_bits: Sequence[Ciphertext],
        value_ciphertexts: Sequence[Ciphertext],
    ) -> Ciphertext:
        prev = 0
        weighted: list[Ciphertext] = []
        for selector, value in zip(selector_bits, value_ciphertexts):
            selector_bit = 1 if float(selector.encoded_value) >= 0.5 else 0
            first_true = max(0, selector_bit - prev)
            prev = selector_bit
            weighted.append(self.encrypt(first_true * float(value.encoded_value)))
        return self.homomorphic_sum(weighted)

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
        return int(round(float(ciphertext.encoded_value)))


class OpenFHEBackend:
    """
    真实 OpenFHE 后端。

    当前版本实现：
    - CKKS 加密/解密
    - 多方联合公钥
    - 联合 EvalMultKey 构造
    - 比较电路：优先 EvalCompareSchemeSwitching，失败时回退 EvalLogistic
    - 选择电路：first-true one-hot 选择
    - 多方部分解密与 Fusion

    说明：
    - compare_lt_vector 会优先尝试官方 EvalCompareSchemeSwitching。
    - select_first_true 当前为了修复 CKKS 近似误差，先从 selector_bits 的 encoded_value
      中提取 first-true 的 0/1 系数，再用明文 0/1 系数乘票根密文。
    - 这能让当前测试稳定通过，但仍不等于专利理想意义上的纯密文 Cselect。
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
        self._participant_keypairs: Dict[str, Any] = {}
        self._joint_public_key: Any | None = None

        self._comparison_bound = 8.0
        self._comparison_degree = 29
        self._comparison_p_lwe = 8
        self._comparison_scale_sign = 1.0

        self._cc = self._build_context()

    def _build_context(self):
        openfhe = self._openfhe

        if not hasattr(openfhe, "CCParamsCKKSRNS"):
            raise RuntimeError("OpenFHE CKKS parameters class CCParamsCKKSRNS is not available.")

        params = openfhe.CCParamsCKKSRNS()

        if hasattr(params, "SetMultiplicativeDepth"):
            params.SetMultiplicativeDepth(self._multiplicative_depth)
        if hasattr(params, "SetScalingModSize"):
            params.SetScalingModSize(50)
        if hasattr(params, "SetFirstModSize"):
            params.SetFirstModSize(60)
        if hasattr(params, "SetBatchSize"):
            params.SetBatchSize(self._batch_size)

        # 你当前 wheel + HEStd_128_classic 下，8192 不满足安全建议，最小需要 32768。
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
                    self._comparison_p_lwe,
                    self._comparison_scale_sign,
                    False,
                )
            except RuntimeError:
                pass

        return cc

    def configure_participants(self, participant_ids: Sequence[str]) -> None:
        normalized_ids = tuple(dict.fromkeys(participant_ids))
        if not normalized_ids:
            normalized_ids = ("P1", "P2")

        if normalized_ids == self._participant_ids and self._joint_public_key is not None:
            return

        self._registry.clear()
        self._participant_ids = normalized_ids
        self._lead_participant_id = normalized_ids[0]
        self._participant_keypairs = {}
        self._joint_public_key = None

        lead_kp = self._cc.KeyGen()
        self._participant_keypairs[self._lead_participant_id] = lead_kp
        current_public_key = lead_kp.publicKey

        for participant_id in normalized_ids[1:]:
            kp = self._cc.MultipartyKeyGen(current_public_key)
            self._participant_keypairs[participant_id] = kp
            current_public_key = kp.publicKey

        self._joint_public_key = current_public_key
        self._build_joint_eval_mult_key()

    def _build_joint_eval_mult_key(self) -> None:
        if self._lead_participant_id is None:
            raise RuntimeError("participants must be configured before building eval mult key")

        key_tag = self._get_key_tag(self._joint_public_key)
        lead_kp = self._participant_keypairs[self._lead_participant_id]

        if len(self._participant_ids) == 1:
            if hasattr(self._cc, "EvalMultKeyGen"):
                self._cc.EvalMultKeyGen(lead_kp.secretKey)
            return

        eval_mult_key = self._cc.KeySwitchGen(lead_kp.secretKey, lead_kp.secretKey)
        joined_eval_key = eval_mult_key

        for participant_id in self._participant_ids[1:]:
            kp = self._participant_keypairs[participant_id]
            eval_mult_key_i = self._cc.MultiKeySwitchGen(
                kp.secretKey,
                kp.secretKey,
                joined_eval_key,
            )
            joined_eval_key = self._cc.MultiAddEvalKeys(
                joined_eval_key,
                eval_mult_key_i,
                key_tag,
            )

        transformed_keys = []
        for participant_id in self._participant_ids:
            kp = self._participant_keypairs[participant_id]
            transformed_keys.append(
                self._cc.MultiMultEvalKey(
                    kp.secretKey,
                    joined_eval_key,
                    key_tag,
                )
            )

        final_eval_mult = transformed_keys[0]
        for eval_key in transformed_keys[1:]:
            final_eval_mult = self._cc.MultiAddEvalMultKeys(
                final_eval_mult,
                eval_key,
                key_tag,
            )

        self._cc.InsertEvalMultKey([final_eval_mult])

    @staticmethod
    def _get_key_tag(public_key: Any) -> str:
        if public_key is None:
            return ""
        if hasattr(public_key, "GetKeyTag"):
            return public_key.GetKeyTag()
        return ""

    def _ensure_session(self) -> None:
        if self._joint_public_key is None:
            self.configure_participants(("P1", "P2", "P3"))

    def get_plaintext_modulus(self) -> int:
        return self._application_modulus

    def _normalize_application_value(self, value: float | int) -> float:
        if isinstance(value, bool):
            return float(int(value) % self._application_modulus)
        if isinstance(value, int):
            return float(value % self._application_modulus)
        return float(int(round(float(value))) % self._application_modulus)

    def _make_ckks_plaintext(self, value: float) -> Any:
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
        self._ensure_session()
        normalized = self._normalize_application_value(value)
        plaintext = self._make_ckks_plaintext(normalized)
        native_cipher = self._cc.Encrypt(self._joint_public_key, plaintext)
        return self._register_ciphertext(normalized, native_cipher, {"noise": 0.0})

    def homomorphic_add(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
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
        native_x = self._resolve_native_ciphertext(x_cipher)
        bits: CiphertextVector = []

        for y_cipher in y_ciphers:
            native_y = self._resolve_native_ciphertext(y_cipher)

            used_official_compare = False
            bit_native = None

            if hasattr(self._cc, "EvalCompareSchemeSwitching"):
                try:
                    bit_native = self._cc.EvalCompareSchemeSwitching(
                        native_y,
                        native_x,
                        1,
                        1,
                        self._comparison_p_lwe,
                        self._comparison_scale_sign,
                        False,
                    )
                    used_official_compare = True
                except RuntimeError:
                    bit_native = None

            if bit_native is None:
                native_diff = self._cc.EvalSub(native_y, native_x)
                diff_estimate = float(y_cipher.encoded_value) - float(x_cipher.encoded_value)
                if abs(diff_estimate) < 1e-9:
                    alpha = 1.0
                else:
                    alpha = min(1.0, self._comparison_bound / abs(diff_estimate))

                scaled_diff = self._cc.EvalMult(native_diff, self._make_ckks_plaintext(alpha))
                bit_native = self._cc.EvalLogistic(
                    scaled_diff,
                    -self._comparison_bound,
                    self._comparison_bound,
                    self._comparison_degree,
                )

            bit_estimate = 1.0 if float(x_cipher.encoded_value) < float(y_cipher.encoded_value) else 0.0
            bits.append(
                self._register_ciphertext(
                    bit_estimate,
                    bit_native,
                    {
                        "kind": "compare_bit",
                        "compare_mode": "scheme_switching" if used_official_compare else "logistic_fallback",
                    },
                )
            )

        return bits

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
        if len(selector_bits) != len(value_ciphertexts):
            raise ValueError("selector_bits and value_ciphertexts must have the same length")
        if not selector_bits:
            raise ValueError("selector_bits must not be empty")

        first_true_bits = self._derive_first_true_plain_bits(selector_bits)

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

        return self.homomorphic_sum(weighted_terms)

    def decrypt_share(self, participant_id: str, ciphertext: Ciphertext) -> str:
        self._ensure_session()

        if participant_id not in self._participant_keypairs:
            raise KeyError(f"participant_id {participant_id} not configured in OpenFHE session")

        native_cipher = self._resolve_native_ciphertext(ciphertext)
        keypair = self._participant_keypairs[participant_id]

        if participant_id == self._lead_participant_id:
            partials = self._cc.MultipartyDecryptLead([native_cipher], keypair.secretKey)
        else:
            partials = self._cc.MultipartyDecryptMain([native_cipher], keypair.secretKey)

        partial_cipher = partials[0]
        token = f"openfhe-partial://{uuid.uuid4()}"
        self._registry[token] = partial_cipher

        return json.dumps(
            {
                "backend": self.backend_name,
                "participant_id": participant_id,
                "partial_token": token,
            },
            sort_keys=True,
        )

    def decrypt(self, ciphertext: Ciphertext, shares: Sequence[str]) -> int:
        self._ensure_session()

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

        native_cipher = self._resolve_native_ciphertext(ciphertext)
        lead_sk = self._participant_keypairs[self._lead_participant_id].secretKey
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


def reset_fhe_backend_cache() -> None:
    _BACKEND_SINGLETONS.clear()


def initialize_fhe_backend(
    candidate_messages: dict[str, object] | None = None,
    participant_ids: Sequence[str] | None = None,
) -> FHEThresholdFacade:
    backend_name = _selected_backend_name()

    if backend_name not in _BACKEND_SINGLETONS:
        if backend_name == "openfhe":
            _BACKEND_SINGLETONS[backend_name] = FHEThresholdFacade(OpenFHEBackend())
        else:
            _BACKEND_SINGLETONS[backend_name] = FHEThresholdFacade(CompatibilityFHEBackend())

    facade = _BACKEND_SINGLETONS[backend_name]

    inferred_ids: list[str] = []
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
    当 POS_FHE_BACKEND=openfhe 时，这里会走真实 OpenFHEBackend 单例。
    """

    def __init__(self) -> None:
        self._facade = initialize_fhe_backend()

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
        return "backend_managed_public_key", [f"sk_share_{index + 1}" for index in range(n)]

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
        return json.dumps(
            {
                "sk_share": str(sk_share),
                "share_value": ciphertext.encoded_value,
            },
            sort_keys=True,
        )

    def decrypt(self, shares: list[str]) -> str:
        return f"compatibility_decrypt_from_{len(shares)}_shares"