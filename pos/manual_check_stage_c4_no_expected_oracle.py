from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


POS_ROOT = Path("/mnt/d/biancheng/pycharm/scientific_project/PoS")
KMS_ROOT = Path("/mnt/d/biancheng/pycharm/scientific_project/kms")

FORBIDDEN = re.compile(
    r"expected_result|expected_index|expected-result|expected-index|POS_KMS_EVAL_.*EXPECTED"
)

POS_PRODUCTION_FILES = [
    POS_ROOT / "pos/crypto/thfhe_backend/kms_eval_bridge.py",
    POS_ROOT / "pos/crypto/thfhe_backend/kms_fhe_backend.py",
]

KMS_BIN_FILE = KMS_ROOT / "core-client/src/bin/kms-tfhe-eval.rs"
KMS_LIB_FILE = KMS_ROOT / "core-client/src/lib.rs"

EVAL_COMMANDS = [
    "eval-add",
    "eval-scale-prf",
    "eval-compare",
    "eval-select",
    "eval-locate",
    "eval-locate-bool",
]


def assert_file_no_forbidden(path: Path, *, start_marker: str | None = None) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")

    if start_marker is not None:
        idx = text.find(start_marker)
        if idx < 0:
            raise AssertionError(f"marker not found in {path}: {start_marker}")
        text = text[idx:]

    matches = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if FORBIDDEN.search(line):
            matches.append(f"{path}:{lineno}: {line}")

    if matches:
        raise AssertionError(
            "Forbidden expected-oracle tokens remain:\n" + "\n".join(matches[:80])
        )


def assert_binary_help_no_forbidden(eval_bin: Path) -> None:
    if not eval_bin.is_file():
        raise AssertionError(f"evaluator binary does not exist: {eval_bin}")

    for command in EVAL_COMMANDS:
        result = subprocess.run(
            [str(eval_bin), command, "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        help_text = result.stdout + "\n" + result.stderr
        if FORBIDDEN.search(help_text):
            raise AssertionError(
                f"Forbidden expected-oracle token appears in help for {command}"
            )


def main() -> None:
    print("=== Stage C-4 No Expected Oracle Check ===")

    for path in POS_PRODUCTION_FILES:
        assert_file_no_forbidden(path)
        print("POS clean:", path)

    assert_file_no_forbidden(KMS_BIN_FILE)
    print("KMS CLI source clean:", KMS_BIN_FILE)

    assert_file_no_forbidden(
        KMS_LIB_FILE,
        start_marker="External evaluator support for PoS KMS/TFHE integration",
    )
    print("KMS external evaluator section clean:", KMS_LIB_FILE)

    eval_bin = Path(
        os.environ.get(
            "POS_KMS_TFHE_EVAL_BIN",
            str(KMS_ROOT / "target/release/kms-tfhe-eval"),
        )
    )
    assert_binary_help_no_forbidden(eval_bin)
    print("KMS evaluator help clean:", eval_bin)

    print("Stage C-4 no expected oracle check passed.")


if __name__ == "__main__":
    main()
