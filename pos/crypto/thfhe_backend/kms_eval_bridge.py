from __future__ import annotations

import json
import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pos.crypto.thfhe_backend.kms_fhe_backend import KmsThresholdCiphertextHandle


class KmsEvalBridgeError(RuntimeError):
    pass


@dataclass(frozen=True)
class KmsEvalConfig:
    evaluator_bin: Path
    server_key_path: Path
    key_id: str
    ciphertext_dir: Path

    @classmethod
    def from_env(cls) -> "KmsEvalConfig":
        evaluator_bin = os.environ.get("POS_KMS_TFHE_EVAL_BIN")
        server_key_path = os.environ.get("POS_KMS_SERVER_KEY_PATH")
        key_id = os.environ.get("POS_KMS_KEY_ID")
        ciphertext_dir = os.environ.get("POS_KMS_CIPHERTEXT_DIR", "/tmp/pos_kms_ciphertexts")

        missing: list[str] = []
        if not evaluator_bin:
            missing.append("POS_KMS_TFHE_EVAL_BIN")
        if not server_key_path:
            missing.append("POS_KMS_SERVER_KEY_PATH")
        if not key_id:
            missing.append("POS_KMS_KEY_ID")

        if missing:
            raise KmsEvalBridgeError(
                "Missing required KMS eval environment variables: "
                + ", ".join(missing)
            )

        cfg = cls(
            evaluator_bin=Path(evaluator_bin).expanduser().resolve(),
            server_key_path=Path(server_key_path).expanduser().resolve(),
            key_id=key_id,
            ciphertext_dir=Path(ciphertext_dir).expanduser().resolve(),
        )

        if not cfg.evaluator_bin.is_file():
            raise KmsEvalBridgeError(f"Evaluator binary does not exist: {cfg.evaluator_bin}")

        if not cfg.server_key_path.is_file():
            raise KmsEvalBridgeError(f"ServerKey file does not exist: {cfg.server_key_path}")

        cfg.ciphertext_dir.mkdir(parents=True, exist_ok=True)
        return cfg


def _euint_bits(data_type: str) -> int:
    match = re.fullmatch(r"euint(\d+)", data_type)
    if match is None:
        raise KmsEvalBridgeError(f"expected encrypted unsigned integer type, got {data_type!r}")

    bits = int(match.group(1))
    if bits not in {8, 16, 32}:
        raise KmsEvalBridgeError(f"unsupported encrypted integer width: {data_type!r}")

    return bits


def _euint_modulus(data_type: str) -> int:
    return 1 << _euint_bits(data_type)


def _ensure_same_euint(
    left: KmsThresholdCiphertextHandle,
    right: KmsThresholdCiphertextHandle,
    *,
    left_label: str = "left",
    right_label: str = "right",
) -> str:
    _euint_bits(left.data_type)
    _euint_bits(right.data_type)

    if left.data_type != right.data_type:
        raise KmsEvalBridgeError(
            f"{left_label} and {right_label} data_type mismatch: "
            f"{left.data_type!r} != {right.data_type!r}"
        )

    return left.data_type




def _kms_uint_modulus(data_type: str) -> int:
    if data_type == "euint8":
        return 1 << 8
    if data_type == "euint16":
        return 1 << 16
    if data_type == "euint32":
        return 1 << 32
    raise KmsEvalBridgeError(f"unsupported KMS unsigned integer data_type: {data_type!r}")


def _kms_uint_bits(data_type: str) -> int:
    if data_type == "euint8":
        return 8
    if data_type == "euint16":
        return 16
    if data_type == "euint32":
        return 32
    raise KmsEvalBridgeError(f"unsupported KMS unsigned integer data_type: {data_type!r}")


def _kms_uint_output_suffix(data_type: str) -> str:
    if data_type in {"euint8", "euint16", "euint32"}:
        return data_type
    raise KmsEvalBridgeError(f"unsupported KMS unsigned integer data_type: {data_type!r}")


class KmsTfheEvalBridge:
    def __init__(self, config: KmsEvalConfig | None = None) -> None:
        self.config = config or KmsEvalConfig.from_env()

    def decode_pair(
        self,
        left: KmsThresholdCiphertextHandle,
        right: KmsThresholdCiphertextHandle,
        *,
        expected_data_type: str = "euint8",
        expected_ct_format: str = "SmallExpanded",
    ) -> dict[str, Any]:
        self._ensure_ciphertext(left)
        self._ensure_ciphertext(right)

        stdout = self._run(
            [
                "decode",
                "--left",
                left.ciphertext_path,
                "--right",
                right.ciphertext_path,
                "--server-key",
                str(self.config.server_key_path),
                "--expected-key-id",
                self.config.key_id,
                "--expected-data-type",
                expected_data_type,
                "--expected-ct-format",
                expected_ct_format,
            ]
        )

        return json.loads(stdout)


    def eval_add(
        self,
        left: KmsThresholdCiphertextHandle,
        right: KmsThresholdCiphertextHandle,
        *,
        expected_result: int,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_ciphertext(left)
        self._ensure_ciphertext(right)

        data_type = _ensure_same_euint(left, right)
        modulus = _euint_modulus(data_type)

        if expected_result < 0 or expected_result >= modulus:
            raise KmsEvalBridgeError(
                f"expected_result must fit {data_type}, got {expected_result}"
            )

        output_id = uuid.uuid4().hex
        output_path = self.config.ciphertext_dir / f"{output_id}.{data_type}.ct"

        stdout = self._run(
            [
                "eval-add",
                "--left",
                left.ciphertext_path,
                "--right",
                right.ciphertext_path,
                "--server-key",
                str(self.config.server_key_path),
                "--output",
                str(output_path),
                "--expected-key-id",
                self.config.key_id,
                "--expected-result",
                str(expected_result),
            ]
        )

        report = json.loads(stdout)
        if report.get("ok") is not True:
            raise KmsEvalBridgeError(f"eval-add did not return ok=true: {report}")

        if not output_path.is_file():
            raise KmsEvalBridgeError(f"eval-add did not create output file: {output_path}")

        return KmsThresholdCiphertextHandle(
            backend="kms-threshold",
            key_id=self.config.key_id,
            data_type=data_type,
            ciphertext_path=str(output_path),
            ciphertext_id=output_id,
        )


    def eval_scale_prf(
        self,
        prf: KmsThresholdCiphertextHandle,
        *,
        numerator: int,
        denominator: int,
        expected_result: int,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_ciphertext(prf)

        _euint_bits(prf.data_type)
        modulus = _euint_modulus(prf.data_type)

        if numerator < 0:
            raise KmsEvalBridgeError(f"numerator must be non-negative, got {numerator}")
        if denominator <= 0:
            raise KmsEvalBridgeError(f"denominator must be positive, got {denominator}")
        if expected_result < 0 or expected_result >= modulus:
            raise KmsEvalBridgeError(
                f"expected_result must fit {prf.data_type}, got {expected_result}"
            )

        output_id = uuid.uuid4().hex
        output_path = self.config.ciphertext_dir / f"{output_id}.{prf.data_type}.ct"

        stdout = self._run(
            [
                "eval-scale-prf",
                "--prf",
                prf.ciphertext_path,
                "--server-key",
                str(self.config.server_key_path),
                "--output",
                str(output_path),
                "--expected-key-id",
                self.config.key_id,
                "--numerator",
                str(numerator),
                "--denominator",
                str(denominator),
                "--expected-result",
                str(expected_result),
            ]
        )

        report = json.loads(stdout)
        if report.get("ok") is not True:
            raise KmsEvalBridgeError(f"eval-scale-prf did not return ok=true: {report}")

        if not output_path.is_file():
            raise KmsEvalBridgeError(f"eval-scale-prf did not create output file: {output_path}")

        return KmsThresholdCiphertextHandle(
            backend="kms-threshold",
            key_id=self.config.key_id,
            data_type=prf.data_type,
            ciphertext_path=str(output_path),
            ciphertext_id=output_id,
        )


    def eval_compare(
        self,
        left: KmsThresholdCiphertextHandle,
        right: KmsThresholdCiphertextHandle,
        *,
        expected_result: bool,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_ciphertext(left)
        self._ensure_ciphertext(right)

        output_id = uuid.uuid4().hex
        output_path = self.config.ciphertext_dir / f"{output_id}.ebool.ct"

        stdout = self._run(
            [
                "eval-compare",
                "--left",
                left.ciphertext_path,
                "--right",
                right.ciphertext_path,
                "--server-key",
                str(self.config.server_key_path),
                "--output",
                str(output_path),
                "--expected-key-id",
                self.config.key_id,
                "--expected-result",
                "true" if expected_result else "false",
            ]
        )

        report = json.loads(stdout)
        if report.get("ok") is not True:
            raise KmsEvalBridgeError(f"eval-compare did not return ok=true: {report}")

        if not output_path.is_file():
            raise KmsEvalBridgeError(f"eval-compare did not create output file: {output_path}")

        return KmsThresholdCiphertextHandle(
            backend="kms-threshold",
            key_id=self.config.key_id,
            data_type="ebool",
            ciphertext_path=str(output_path),
            ciphertext_id=output_id,
        )

    def eval_select(
        self,
        selector: KmsThresholdCiphertextHandle,
        true_value: KmsThresholdCiphertextHandle,
        false_value: KmsThresholdCiphertextHandle,
        *,
        expected_result: int,
    ) -> KmsThresholdCiphertextHandle:
        self._ensure_ciphertext(selector)
        self._ensure_ciphertext(true_value)
        self._ensure_ciphertext(false_value)

        if selector.data_type != "ebool":
            raise KmsEvalBridgeError(f"selector must be ebool, got {selector.data_type!r}")

        data_type = _ensure_same_euint(
            true_value,
            false_value,
            left_label="true_value",
            right_label="false_value",
        )
        modulus = _euint_modulus(data_type)

        if expected_result < 0 or expected_result >= modulus:
            raise KmsEvalBridgeError(
                f"expected_result must fit {data_type}, got {expected_result}"
            )

        output_id = uuid.uuid4().hex
        output_path = self.config.ciphertext_dir / f"{output_id}.{data_type}.ct"

        stdout = self._run(
            [
                "eval-select",
                "--selector",
                selector.ciphertext_path,
                "--true-value",
                true_value.ciphertext_path,
                "--false-value",
                false_value.ciphertext_path,
                "--server-key",
                str(self.config.server_key_path),
                "--output",
                str(output_path),
                "--expected-key-id",
                self.config.key_id,
                "--expected-result",
                str(expected_result),
            ]
        )

        report = json.loads(stdout)
        if report.get("ok") is not True:
            raise KmsEvalBridgeError(f"eval-select did not return ok=true: {report}")

        if not output_path.is_file():
            raise KmsEvalBridgeError(f"eval-select did not create output file: {output_path}")

        return KmsThresholdCiphertextHandle(
            backend="kms-threshold",
            key_id=self.config.key_id,
            data_type=data_type,
            ciphertext_path=str(output_path),
            ciphertext_id=output_id,
        )


    def eval_locate(
        self,
        values: list[KmsThresholdCiphertextHandle],
        *,
        expected_index: int,
    ) -> list[KmsThresholdCiphertextHandle]:
        if not values:
            raise KmsEvalBridgeError("eval_locate requires at least one ciphertext")

        if expected_index < 0 or expected_index >= len(values):
            raise KmsEvalBridgeError(
                f"expected_index {expected_index} out of range for {len(values)} values"
            )

        for idx, value in enumerate(values):
            self._ensure_ciphertext(value)
            _euint_bits(value.data_type)

        output_id = uuid.uuid4().hex
        output_dir = self.config.ciphertext_dir / f"{output_id}.locate"
        output_dir.mkdir(parents=True, exist_ok=True)

        command_args: list[str] = ["eval-locate"]

        for value in values:
            command_args.extend(["--value", value.ciphertext_path])

        command_args.extend(
            [
                "--server-key",
                str(self.config.server_key_path),
                "--output-dir",
                str(output_dir),
                "--expected-key-id",
                self.config.key_id,
                "--expected-index",
                str(expected_index),
            ]
        )

        stdout = self._run(command_args)
        report = json.loads(stdout)

        if report.get("ok") is not True:
            raise KmsEvalBridgeError(f"eval-locate did not return ok=true: {report}")

        outputs = report.get("outputs")
        if not isinstance(outputs, list) or len(outputs) != len(values):
            raise KmsEvalBridgeError(f"eval-locate returned invalid outputs: {report}")

        handles: list[KmsThresholdCiphertextHandle] = []
        for idx, output in enumerate(outputs):
            output_path = Path(output["path"])
            if not output_path.is_file():
                raise KmsEvalBridgeError(f"eval-locate output file does not exist: {output_path}")

            handles.append(
                KmsThresholdCiphertextHandle(
                    backend="kms-threshold",
                    key_id=self.config.key_id,
                    data_type="ebool",
                    ciphertext_path=str(output_path),
                    ciphertext_id=f"{output_id}_onehot_{idx:02}",
                )
            )

        return handles


    def eval_locate_first_true(
        self,
        flags: list[KmsThresholdCiphertextHandle],
        *,
        expected_index: int,
    ) -> list[KmsThresholdCiphertextHandle]:
        if not flags:
            raise KmsEvalBridgeError("eval_locate_first_true requires at least one flag")

        if expected_index < 0 or expected_index >= len(flags):
            raise KmsEvalBridgeError(
                f"expected_index {expected_index} out of range for {len(flags)} flags"
            )

        for idx, flag in enumerate(flags):
            self._ensure_ciphertext(flag)
            if flag.data_type != "ebool":
                raise KmsEvalBridgeError(f"flag[{idx}] must be ebool, got {flag.data_type!r}")

        output_id = uuid.uuid4().hex
        output_dir = self.config.ciphertext_dir / f"{output_id}.first_true"
        output_dir.mkdir(parents=True, exist_ok=True)

        command_args: list[str] = ["eval-locate-bool"]

        for flag in flags:
            command_args.extend(["--flag", flag.ciphertext_path])

        command_args.extend(
            [
                "--server-key",
                str(self.config.server_key_path),
                "--output-dir",
                str(output_dir),
                "--expected-key-id",
                self.config.key_id,
                "--expected-index",
                str(expected_index),
            ]
        )

        stdout = self._run(command_args)
        report = json.loads(stdout)

        if report.get("ok") is not True:
            raise KmsEvalBridgeError(f"eval-locate-bool did not return ok=true: {report}")

        outputs = report.get("outputs")
        if not isinstance(outputs, list) or len(outputs) != len(flags):
            raise KmsEvalBridgeError(f"eval-locate-bool returned invalid outputs: {report}")

        handles: list[KmsThresholdCiphertextHandle] = []
        for idx, output in enumerate(outputs):
            output_path = Path(output["path"])
            if not output_path.is_file():
                raise KmsEvalBridgeError(f"eval-locate-bool output file does not exist: {output_path}")

            handles.append(
                KmsThresholdCiphertextHandle(
                    backend="kms-threshold",
                    key_id=self.config.key_id,
                    data_type="ebool",
                    ciphertext_path=str(output_path),
                    ciphertext_id=f"{output_id}_first_true_{idx:02}",
                )
            )

        return handles


    def _ensure_ciphertext(self, ciphertext: KmsThresholdCiphertextHandle) -> None:
        if ciphertext.backend != "kms-threshold":
            raise KmsEvalBridgeError(
                f"Expected kms-threshold ciphertext, got {ciphertext.backend!r}"
            )

        if ciphertext.key_id != self.config.key_id:
            raise KmsEvalBridgeError(
                f"Ciphertext key_id mismatch: {ciphertext.key_id!r} != {self.config.key_id!r}"
            )

        path = Path(ciphertext.ciphertext_path)
        if not path.is_file():
            raise KmsEvalBridgeError(f"Ciphertext file does not exist: {path}")

    def _run(self, args: list[str]) -> str:
        command = [str(self.config.evaluator_bin), *args]

        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if result.returncode != 0:
            raise KmsEvalBridgeError(
                "KMS TFHE evaluator command failed\n"
                f"command: {' '.join(command)}\n"
                f"returncode: {result.returncode}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )

        return result.stdout
