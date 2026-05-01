from __future__ import annotations

import os
from pathlib import Path

from pos.crypto.thfhe_backend.kms_eval_oracle_guard import (
    KmsOracleEvaluatorForbiddenError,
    assert_no_expected_oracle_evaluator,
)


def write_fake_oracle_evaluator(path: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "if [ \"$1\" = \"--help\" ]; then\n"
        "  echo 'kms-tfhe-eval fake help --expected-result --expected-index'\n"
        "  exit 0\n"
        "fi\n"
        "echo 'fake evaluator'\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def main() -> None:
    print("=== Stage C-1 Oracle Evaluator Guard Check ===")

    os.environ["POS_STRICT_PATENT_MODE"] = "1"
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"

    original_eval_bin = os.environ.get("POS_KMS_TFHE_EVAL_BIN")

    fake_path = Path("/tmp/stage_c1_fake_kms_tfhe_eval")
    write_fake_oracle_evaluator(fake_path)

    os.environ["POS_KMS_TFHE_EVAL_BIN"] = str(fake_path)

    blocked_fake = False
    try:
        assert_no_expected_oracle_evaluator()
    except KmsOracleEvaluatorForbiddenError as exc:
        blocked_fake = True
        print("blocked_fake_oracle:", True)
        print("fake_block_reason:", str(exc).splitlines()[0])

    if not blocked_fake:
        raise AssertionError("strict guard failed to block fake expected-oracle evaluator")

    if original_eval_bin:
        os.environ["POS_KMS_TFHE_EVAL_BIN"] = original_eval_bin
        try:
            assert_no_expected_oracle_evaluator()
        except KmsOracleEvaluatorForbiddenError as exc:
            print("real_evaluator_blocked:", True)
            print("real_block_reason:", str(exc).splitlines()[0])
        else:
            print("real_evaluator_blocked:", False)
            print("real_evaluator_status:", "no expected oracle detected in --help")
    else:
        print("real_evaluator_check:", "skipped because original POS_KMS_TFHE_EVAL_BIN was not set")

    print("Stage C-1 oracle evaluator guard check passed.")


if __name__ == "__main__":
    main()
