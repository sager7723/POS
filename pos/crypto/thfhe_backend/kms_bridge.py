from __future__ import annotations

import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class KmsBridgeError(RuntimeError):
    pass


class KmsCommandError(KmsBridgeError):
    def __init__(self, command: Sequence[str], returncode: int, stdout: str, stderr: str) -> None:
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            "KMS command failed\n"
            f"command: {' '.join(self.command)}\n"
            f"returncode: {returncode}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )


@dataclass(frozen=True)
class KmsBridgeConfig:
    core_client_bin: Path
    core_client_config: Path
    key_id: str
    ciphertext_dir: Path

    @classmethod
    def from_env(cls) -> "KmsBridgeConfig":
        core_client_bin = os.environ.get("POS_KMS_CORE_CLIENT_BIN")
        core_client_config = os.environ.get("POS_KMS_CORE_CLIENT_CONFIG")
        key_id = os.environ.get("POS_KMS_KEY_ID")
        ciphertext_dir = os.environ.get("POS_KMS_CIPHERTEXT_DIR", "/tmp/pos_kms_ciphertexts")

        missing = []
        if not core_client_bin:
            missing.append("POS_KMS_CORE_CLIENT_BIN")
        if not core_client_config:
            missing.append("POS_KMS_CORE_CLIENT_CONFIG")
        if not key_id:
            missing.append("POS_KMS_KEY_ID")

        if missing:
            raise KmsBridgeError(
                "Missing required KMS bridge environment variables: "
                + ", ".join(missing)
            )

        cfg = cls(
            core_client_bin=Path(core_client_bin).expanduser().resolve(),
            core_client_config=Path(core_client_config).expanduser().resolve(),
            key_id=key_id,
            ciphertext_dir=Path(ciphertext_dir).expanduser().resolve(),
        )

        if not cfg.core_client_bin.is_file():
            raise KmsBridgeError(f"POS_KMS_CORE_CLIENT_BIN does not exist: {cfg.core_client_bin}")

        if not cfg.core_client_config.is_file():
            raise KmsBridgeError(
                f"POS_KMS_CORE_CLIENT_CONFIG does not exist: {cfg.core_client_config}"
            )

        cfg.ciphertext_dir.mkdir(parents=True, exist_ok=True)
        return cfg


@dataclass(frozen=True)
class KmsCiphertext:
    backend: str
    key_id: str
    data_type: str
    ciphertext_path: Path
    ciphertext_id: str

    def to_public_dict(self) -> dict[str, str]:
        return {
            "backend": self.backend,
            "key_id": self.key_id,
            "data_type": self.data_type,
            "ciphertext_path": str(self.ciphertext_path),
            "ciphertext_id": self.ciphertext_id,
        }


class KmsThresholdBridge:
    """
    Project bridge to a real KMS threshold FHE deployment.

    This class intentionally does not store or return encoded_value.
    Encryption returns only an opaque ciphertext file descriptor.
    Decryption is performed by the KMS threshold service through kms-core-client.
    """

    def __init__(self, config: KmsBridgeConfig | None = None) -> None:
        self.config = config or KmsBridgeConfig.from_env()

    def encrypt_scalar(
        self,
        value: int,
        data_type: str = "euint8",
        *,
        no_compression: bool = False,
        no_precompute_sns: bool = False,
    ) -> KmsCiphertext:
        if value < 0:
            raise ValueError("Only non-negative scalar values are supported by this bridge")

        hex_value = self._scalar_to_little_endian_hex(value=value, data_type=data_type)
        ciphertext_id = uuid.uuid4().hex
        output_path = self.config.ciphertext_dir / f"{ciphertext_id}.{data_type}.ct"

        args = [
            "encrypt",
            "--key-id",
            self.config.key_id,
            "--data-type",
            data_type,
            "--to-encrypt",
            hex_value,
            "--ciphertext-output-path",
            str(output_path),
        ]

        if no_compression:
            args.append("--no-compression")

        if no_precompute_sns:
            args.append("--no-precompute-sns")

        self._run_core_client(args)

        if not output_path.is_file():
            raise KmsBridgeError(f"KMS encryption did not create ciphertext file: {output_path}")

        return KmsCiphertext(
            backend="kms-threshold",
            key_id=self.config.key_id,
            data_type=data_type,
            ciphertext_path=output_path,
            ciphertext_id=ciphertext_id,
        )

    def user_decrypt_scalar(self, ciphertext: KmsCiphertext) -> int:
        stdout = self._run_core_client(
            [
                "user-decrypt",
                "from-file",
                "--input-path",
                str(ciphertext.ciphertext_path),
            ]
        )
        return self._parse_user_decrypt_plaintext(stdout)

    def public_decrypt_scalar(self, ciphertext: KmsCiphertext) -> int:
        stdout = self._run_core_client(
            [
                "public-decrypt",
                "from-file",
                "--input-path",
                str(ciphertext.ciphertext_path),
            ]
        )
        return self._parse_public_decrypt_plaintext(stdout, data_type=ciphertext.data_type)

    def _run_core_client(self, args: Sequence[str]) -> str:
        command = [
            str(self.config.core_client_bin),
            "-f",
            str(self.config.core_client_config),
            *args,
        ]

        env = os.environ.copy()
        env.setdefault("KMS_CORE_CLIENT_SKIP_FROM_FILE_PLAINTEXT_CHECK", "1")

        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

        if result.returncode != 0:
            raise KmsCommandError(
                command=command,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )

        return result.stdout

    @staticmethod
    def _scalar_to_little_endian_hex(value: int, data_type: str) -> str:
        bit_width = KmsThresholdBridge._data_type_bits(data_type)
        byte_width = max(1, bit_width // 8)
        max_value = (1 << bit_width) - 1

        if value > max_value:
            raise ValueError(f"value={value} does not fit in {data_type}")

        return value.to_bytes(byte_width, byteorder="little", signed=False).hex()

    @staticmethod
    def _data_type_bits(data_type: str) -> int:
        if data_type == "ebool":
            return 8

        match = re.fullmatch(r"euint(\d+)", data_type)
        if not match:
            raise ValueError(f"Unsupported KMS data_type: {data_type}")

        bits = int(match.group(1))
        if bits <= 0 or bits % 8 != 0:
            raise ValueError(f"Unsupported KMS integer width: {data_type}")

        return bits

    @staticmethod
    def _parse_user_decrypt_plaintext(stdout: str) -> int:
        match = re.search(r"User decrypted Plaintext\s+([A-Za-z0-9]+)\(([^)]+)\)", stdout)
        if not match:
            raise KmsBridgeError(f"Could not parse user-decrypt plaintext from stdout:\n{stdout}")

        value_text = match.group(2).strip()

        if value_text.lower() == "true":
            return 1

        if value_text.lower() == "false":
            return 0

        return int(value_text, 10)


    def _parse_public_decrypt_plaintext(self, stdout: str, *, data_type: str | None = None) -> int:
        import ast
        import re

        text = stdout.strip()

        bool_match = re.search(r"Bool\\((true|false)\\)", text, re.IGNORECASE)
        if bool_match:
            return 1 if bool_match.group(1).lower() == "true" else 0

        typed_number_match = re.search(
            r"(?:U|Uint|Euint)(?:8|16|32|64)\\((\\d+)\\)",
            text,
            re.IGNORECASE,
        )
        if typed_number_match:
            return int(typed_number_match.group(1), 10)

        def expected_byte_width() -> int | None:
            if data_type is None:
                return None
            return max(1, self._data_type_bits(data_type) // 8)

        def parse_byte_token(token: str, *, prefer_hex: bool) -> int:
            raw = token.strip()
            if not raw:
                raise ValueError("empty byte token")

            if raw.startswith(("b'", 'b"')):
                value = ast.literal_eval(raw)
                if not isinstance(value, (bytes, bytearray)) or len(value) == 0:
                    raise ValueError(f"invalid bytes literal: {raw!r}")
                byte_value = int(value[0])
            else:
                cleaned = raw.strip().strip('"').strip("'")

                escaped_hex = re.fullmatch(r"\\x([0-9a-fA-F]{2})", cleaned)
                if escaped_hex:
                    byte_value = int(escaped_hex.group(1), 16)
                elif cleaned.lower().startswith("0x"):
                    byte_value = int(cleaned, 16)
                elif re.fullmatch(r"[0-9a-fA-F]{1,2}", cleaned) and (
                    prefer_hex or re.search(r"[a-fA-F]", cleaned)
                ):
                    byte_value = int(cleaned, 16)
                else:
                    byte_value = int(cleaned, 10)

            if byte_value < 0 or byte_value > 255:
                raise ValueError(f"byte token out of range: {token!r} -> {byte_value}")

            return byte_value

        def parse_byte_list(byte_text: str, *, prefer_hex: bool) -> int:
            parts = [part.strip() for part in byte_text.split(",") if part.strip()]
            if not parts and byte_text.strip():
                parts = [byte_text.strip()]
            if not parts:
                raise ValueError(f"Could not parse public decrypt bytes from stdout:\n{text}")

            byte_values = [parse_byte_token(part, prefer_hex=prefer_hex) for part in parts]

            width = expected_byte_width()
            if width is not None:
                if len(byte_values) < width:
                    raise ValueError(
                        f"public decrypt returned {len(byte_values)} byte(s), "
                        f"but {data_type} requires {width}:\n{text}"
                    )
                byte_values = byte_values[:width]

            return int.from_bytes(bytes(byte_values), byteorder="little", signed=False)

        typed_plaintext_match = re.search(
            r"plaintexts:\s*\[\s*TypedPlaintext\s*\{\s*bytes:\s*\[(.*?)\]\s*,\s*fhe_type:\s*\d+\s*\}",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        if typed_plaintext_match:
            return parse_byte_list(typed_plaintext_match.group(1), prefer_hex=False)

        bytes_list_match = re.search(r"Bytes\(\[(.*?)\]\)", text, re.IGNORECASE | re.DOTALL)
        if bytes_list_match:
            # KMS public-decrypt Bytes output may print raw hex-like tokens:
            #   Bytes([fe, ca]) -> little-endian 0xcafe
            #   Bytes([16])     -> 0x16 -> 22
            return parse_byte_list(bytes_list_match.group(1), prefer_hex=True)

        bytes_match = re.search(r"Bytes\((.*?)\)", text, re.IGNORECASE | re.DOTALL)
        if bytes_match:
            byte_text = bytes_match.group(1).strip()
            if byte_text:
                return parse_byte_list(byte_text, prefer_hex=True)

        raise ValueError(f"Could not parse public decrypt plaintext from stdout:\n{text}")
