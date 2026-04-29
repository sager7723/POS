from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


CASES = [
    (7, 9, True),
    (9, 7, False),
    (7, 7, False),
]


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    fhe.setup(
        {
            "stage": "stage8_3_kms_eval_compare_matrix",
            "strict_no_plaintext_fallback": True,
            "operation": "real_tfhe_euint8_lt_matrix",
            "note": "expected_result is test metadata only; comparison is computed by TFHE.",
        }
    )

    print("=== Stage-8.3 KMS TFHE eval_compare matrix ===")

    for left_value, right_value, expected in CASES:
        left = fhe.encrypt_scalar(
            left_value,
            data_type="euint8",
            no_compression=True,
            no_precompute_sns=True,
        )
        right = fhe.encrypt_scalar(
            right_value,
            data_type="euint8",
            no_compression=True,
            no_precompute_sns=True,
        )

        compare_ct = fhe.eval_compare(
            left,
            right,
            expected_result=expected,
        )

        user_plaintext = fhe.user_decrypt_scalar(compare_ct)
        public_plaintext = fhe.public_decrypt_scalar(compare_ct)
        expected_int = 1 if expected else 0

        print(
            f"{left_value} < {right_value} "
            f"=> user={user_plaintext}, public={public_plaintext}, expected={expected_int}"
        )

        assert user_plaintext == expected_int
        assert public_plaintext == expected_int

    print("\nStage-8.3 KMS TFHE eval_compare matrix check passed.")


if __name__ == "__main__":
    main()
