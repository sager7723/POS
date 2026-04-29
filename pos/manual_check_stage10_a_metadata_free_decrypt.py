from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def encrypt_u8(fhe, value: int):
    return fhe.encrypt_scalar(
        value,
        data_type="euint8",
        no_compression=True,
        no_precompute_sns=True,
    )


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3"],
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    fhe.setup(
        {
            "stage": "stage10_a_metadata_free_decrypt",
            "strict_no_plaintext_fallback": True,
            "operation": "kms_metadata_free_from_file_decrypt",
        }
    )

    left = encrypt_u8(fhe, 7)
    right = encrypt_u8(fhe, 9)

    # Deliberately omit expected_result.
    # The current eval_add default metadata is 0, while real encrypted result is 16.
    sum_ct = fhe.eval_add(left, right)

    user_plain = fhe.user_decrypt_scalar(sum_ct)
    public_plain = fhe.public_decrypt_scalar(sum_ct)

    print("=== Stage-10-A metadata-free KMS decrypt ===")
    print("expected_real_sum:", 16)
    print("user_plain:", user_plain)
    print("public_plain:", public_plain)

    assert user_plain == 16
    assert public_plain == 16

    print("\nStage-10-A metadata-free KMS decrypt check passed.")


if __name__ == "__main__":
    main()
