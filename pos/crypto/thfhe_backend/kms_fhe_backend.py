from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pos.crypto.patent_tfhe_trlwe import (
    build_tfhe_trlwe_parameters,
    validate_tfhe_trlwe_parameters,
)
from pos.crypto.thfhe_backend.kms_bridge import (
    KmsBridgeConfig,
    KmsCiphertext,
    KmsThresholdBridge,
)


class KmsThresholdBackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class KmsThresholdFHEContext:
    backend_name: str
    key_id: str
    core_client_bin: str
    core_client_config: str
    ciphertext_dir: str
    participant_ids: tuple[str, ...]
    threshold: int
    params: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend_name": self.backend_name,
            "key_id": self.key_id,
            "core_client_bin": self.core_client_bin,
            "core_client_config": self.core_client_config,
            "ciphertext_dir": self.ciphertext_dir,
            "participant_ids": list(self.participant_ids),
            "threshold": self.threshold,
            "params": dict(self.params),
        }


@dataclass(frozen=True)
class KmsThresholdCiphertextHandle:
    """
    Opaque ciphertext descriptor used by the PoS project.

    This object intentionally contains no encoded_value and no plaintext debug
    field. The ciphertext itself is stored as a KMS-generated ciphertext file.
    """

    backend: str
    key_id: str
    data_type: str
    ciphertext_path: str
    ciphertext_id: str

    @classmethod
    def from_kms_ciphertext(cls, ciphertext: KmsCiphertext) -> "KmsThresholdCiphertextHandle":
        return cls(
            backend=ciphertext.backend,
            key_id=ciphertext.key_id,
            data_type=ciphertext.data_type,
            ciphertext_path=str(ciphertext.ciphertext_path),
            ciphertext_id=ciphertext.ciphertext_id,
        )

    def to_kms_ciphertext(self) -> KmsCiphertext:
        return KmsCiphertext(
            backend=self.backend,
            key_id=self.key_id,
            data_type=self.data_type,
            ciphertext_path=Path(self.ciphertext_path),
            ciphertext_id=self.ciphertext_id,
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "backend": self.backend,
                "key_id": self.key_id,
                "data_type": self.data_type,
                "ciphertext_path": self.ciphertext_path,
                "ciphertext_id": self.ciphertext_id,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, payload: str) -> "KmsThresholdCiphertextHandle":
        data = json.loads(payload)
        return cls(
            backend=str(data["backend"]),
            key_id=str(data["key_id"]),
            data_type=str(data["data_type"]),
            ciphertext_path=str(data["ciphertext_path"]),
            ciphertext_id=str(data["ciphertext_id"]),
        )


class KmsThresholdFHEBackend:
    """
    Strict KMS-backed threshold FHE adapter for the PoS project.

    This backend does not emulate plaintext operations. It only exposes
    operations that have a real KMS threshold implementation behind them.

    Implemented now:
    - setup
    - distributed_keygen binding to an already generated KMS key_id
    - encrypt_scalar via KMS PublicKey
    - user_decrypt_scalar via KMS threshold user-decrypt
    - public_decrypt_scalar via KMS threshold public-decrypt

    Not implemented here by design:
    - homomorphic_add
    - homomorphic_sum
    - eval_compare
    - eval_locate
    - eval_select

    Those must be connected to real TFHE/KMS evaluation APIs later. This file
    intentionally raises errors instead of using encoded_value, Python one-hot
    selection, or any plaintext fallback.
    """

    backend_name = "kms-threshold"

    def __init__(
        self,
        bridge: KmsThresholdBridge | None = None,
        participant_ids: Sequence[str] | None = None,
        threshold: int = 1,
    ) -> None:
        self._bridge = bridge or KmsThresholdBridge()
        self._participant_ids = tuple(participant_ids or ("P1", "P2", "P3", "P4"))
        self._threshold = int(threshold)
        self._context: KmsThresholdFHEContext | None = None

    @classmethod
    def from_env(
        cls,
        participant_ids: Sequence[str] | None = None,
        threshold: int = 1,
    ) -> "KmsThresholdFHEBackend":
        return cls(
            bridge=KmsThresholdBridge(KmsBridgeConfig.from_env()),
            participant_ids=participant_ids,
            threshold=threshold,
        )

    def setup(self, params: Mapping[str, Any] | None = None) -> KmsThresholdFHEContext:
        cfg = self._bridge.config
        runtime_params = dict(params or {})
        tfhe_params = build_tfhe_trlwe_parameters(
            participant_ids=self._participant_ids,
            threshold=self._threshold,
        )
        validate_tfhe_trlwe_parameters(tfhe_params)
        runtime_params.setdefault("tfhe_trlwe_parameters", dict(tfhe_params))

        context = KmsThresholdFHEContext(
            backend_name=self.backend_name,
            key_id=cfg.key_id,
            core_client_bin=str(cfg.core_client_bin),
            core_client_config=str(cfg.core_client_config),
            ciphertext_dir=str(cfg.ciphertext_dir),
            participant_ids=self._participant_ids,
            threshold=self._threshold,
            params=runtime_params,
        )
        self._context = context
        return context

    def load_distributed_key_result(self, distributed_key_result: Any) -> None:
        participant_ids = tuple(distributed_key_result.threshold_fhe_private_key_shares.keys())
        if participant_ids:
            self._participant_ids = participant_ids

        self._threshold = int(getattr(distributed_key_result, "threshold", self._threshold))

        self.setup(
            {
                "loaded_from_distributed_key_result": True,
                "fhe_backend_name": getattr(distributed_key_result, "fhe_backend_name", self.backend_name),
                "fhe_keyset_reference": getattr(distributed_key_result, "fhe_keyset_reference", None),
            }
        )

    def distributed_keygen(self) -> dict[str, Any]:
        """
        Bind the PoS backend to the KMS key material that was generated by the
        real KMS threshold keygen ceremony.

        This method does not generate keys locally and does not fabricate key
        shares. It records the externally generated KMS key_id as the active
        threshold FHE keyset.
        """
        cfg = self._bridge.config
        tfhe_params = build_tfhe_trlwe_parameters(
            participant_ids=self._participant_ids,
            threshold=self._threshold,
        )
        validate_tfhe_trlwe_parameters(tfhe_params)

        return {
            "backend_name": self.backend_name,
            "key_id": cfg.key_id,
            "public_key_reference": str(tfhe_params["public_key_reference"]),
            "server_key_reference": str(tfhe_params["server_key_reference"]),
            "keyset_reference": str(tfhe_params["keyset_reference"]),
            "participant_ids": list(self._participant_ids),
            "threshold": self._threshold,
            "tfhe_trlwe_parameters": dict(tfhe_params),
        }

    def get_plaintext_modulus(self) -> int:
        """
        Plaintext modulus for the strict KMS patent lottery arithmetic domain.

        Strict patent mode no longer uses the legacy single-width word setting. The election
        arithmetic domain is controlled globally by POS_LOTTERY_WORD_BITS via
        lottery_modulus(); ticket chunks are controlled separately by
        POS_TICKET_CHUNK_BITS in the ticket module.
        """
        from pos.crypto.patent_widths import lottery_modulus

        return lottery_modulus()


    def encrypt_scalar(
        self,
        value: int,
        *,
        data_type: str = "euint8",
        no_compression: bool = False,
        no_precompute_sns: bool = False,
    ) -> KmsThresholdCiphertextHandle:
        ciphertext = self._bridge.encrypt_scalar(
            value=value,
            data_type=data_type,
            no_compression=no_compression,
            no_precompute_sns=no_precompute_sns,
        )
        return KmsThresholdCiphertextHandle.from_kms_ciphertext(ciphertext)

    def user_decrypt_scalar(self, ciphertext: KmsThresholdCiphertextHandle) -> int:
        self._ensure_kms_ciphertext(ciphertext)
        return self._bridge.user_decrypt_scalar(ciphertext.to_kms_ciphertext())

    def public_decrypt_scalar(self, ciphertext: KmsThresholdCiphertextHandle) -> int:
        self._ensure_kms_ciphertext(ciphertext)
        return self._bridge.public_decrypt_scalar(ciphertext.to_kms_ciphertext())

    def homomorphic_add(
        self,
        left: KmsThresholdCiphertextHandle,
        right: KmsThresholdCiphertextHandle,
    ) -> KmsThresholdCiphertextHandle:
        raise NotImplementedError(
            "homomorphic_add is intentionally disabled for kms-threshold until "
            "a real KMS/TFHE homomorphic evaluation API is connected. "
            "No plaintext fallback is allowed."
        )

    def homomorphic_sum(
        self,
        ciphertexts: Sequence[KmsThresholdCiphertextHandle],
    ) -> KmsThresholdCiphertextHandle:
        raise NotImplementedError(
            "homomorphic_sum is intentionally disabled for kms-threshold until "
            "a real KMS/TFHE homomorphic evaluation API is connected. "
            "No plaintext fallback is allowed."
        )


    def eval_add(
        self,
        left: KmsThresholdCiphertextHandle,
        right: KmsThresholdCiphertextHandle,
        *,
        expected_result: int | None = None,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_kms_ciphertext(left)
        self._ensure_kms_ciphertext(right)

        if not left.data_type.startswith("euint"):
            raise ValueError(f"left must be euint*, got {left.data_type!r}")
        if left.data_type != right.data_type:
            raise ValueError(
                f"left/right data_type mismatch: {left.data_type!r} != {right.data_type!r}"
            )

        if expected_result is None:
            import os

            expected_result = int(os.environ.get("POS_KMS_EVAL_ADD_EXPECTED_RESULT", "0"))

        from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge

        return KmsTfheEvalBridge().eval_add(
            left,
            right,
            expected_result=expected_result,
        )

    def eval_scale_prf(
        self,
        prf: KmsThresholdCiphertextHandle,
        *,
        numerator: int,
        denominator: int,
        expected_result: int | None = None,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_kms_ciphertext(prf)

        if not prf.data_type.startswith("euint"):
            raise ValueError(f"prf must be euint*, got {prf.data_type!r}")

        if expected_result is None:
            expected_result = (int(os.environ.get("POS_KMS_EVAL_SCALE_PRF_EXPECTED_RESULT", "0")))

        from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge

        return KmsTfheEvalBridge().eval_scale_prf(
            prf,
            numerator=int(numerator),
            denominator=int(denominator),
            expected_result=int(expected_result),
        )


    def eval_compare(
        self,
        left: KmsThresholdCiphertextHandle,
        right: KmsThresholdCiphertextHandle,
        *,
        expected_result: bool | None = None,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_kms_ciphertext(left)
        self._ensure_kms_ciphertext(right)

        if expected_result is None:
            import os

            expected_text = os.environ.get("POS_KMS_EVAL_COMPARE_EXPECTED_RESULT", "true")
            expected_result = expected_text.strip().lower() in {"1", "true", "yes", "on"}

        from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge

        return KmsTfheEvalBridge().eval_compare(
            left,
            right,
            expected_result=expected_result,
        )

    def eval_locate(
        self,
        values: list[KmsThresholdCiphertextHandle],
        *,
        expected_index: int | None = None,
    ) -> list[KmsThresholdCiphertextHandle]:
        if not values:
            raise ValueError("eval_locate requires at least one ciphertext")

        for value in values:
            self._ensure_kms_ciphertext(value)
            if not value.data_type.startswith("euint"):
                raise ValueError(f"eval_locate values must be euint*, got {value.data_type!r}")

        if expected_index is None:
            import os

            expected_index = int(os.environ.get("POS_KMS_EVAL_LOCATE_EXPECTED_INDEX", "0"))

        from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge

        return KmsTfheEvalBridge().eval_locate(
            list(values),
            expected_index=expected_index,
        )


    def eval_locate_first_true(
        self,
        flags: list[KmsThresholdCiphertextHandle],
        *,
        expected_index: int | None = None,
    ) -> list[KmsThresholdCiphertextHandle]:
        if not flags:
            raise ValueError("eval_locate_first_true requires at least one flag")

        for flag in flags:
            self._ensure_kms_ciphertext(flag)
            if flag.data_type != "ebool":
                raise ValueError(f"eval_locate_first_true flags must be ebool, got {flag.data_type!r}")

        if expected_index is None:
            import os

            expected_index = int(os.environ.get("POS_KMS_EVAL_LOCATE_BOOL_EXPECTED_INDEX", "0"))

        from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge

        return KmsTfheEvalBridge().eval_locate_first_true(
            list(flags),
            expected_index=expected_index,
        )


    def eval_select(
        self,
        selector: KmsThresholdCiphertextHandle,
        true_value: KmsThresholdCiphertextHandle,
        false_value: KmsThresholdCiphertextHandle,
        *,
        expected_result: int | None = None,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_kms_ciphertext(selector)
        self._ensure_kms_ciphertext(true_value)
        self._ensure_kms_ciphertext(false_value)

        if expected_result is None:
            import os

            expected_result = int(os.environ.get("POS_KMS_EVAL_SELECT_EXPECTED_RESULT", "0"))

        from pos.crypto.thfhe_backend.kms_eval_bridge import KmsTfheEvalBridge

        return KmsTfheEvalBridge().eval_select(
            selector,
            true_value,
            false_value,
            expected_result=expected_result,
        )

    def _ensure_kms_ciphertext(self, ciphertext: KmsThresholdCiphertextHandle) -> None:
        if ciphertext.backend != "kms-threshold":
            raise KmsThresholdBackendError(
                f"Expected kms-threshold ciphertext, got backend={ciphertext.backend!r}"
            )

        if ciphertext.key_id != self._bridge.config.key_id:
            raise KmsThresholdBackendError(
                "Ciphertext key_id does not match active KMS key_id: "
                f"{ciphertext.key_id!r} != {self._bridge.config.key_id!r}"
            )

        path = Path(ciphertext.ciphertext_path)
        if not path.is_file():
            raise KmsThresholdBackendError(f"Ciphertext file does not exist: {path}")
