from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


CASES = [
    ([13, 7, 22, 9], 1),
    ([7, 7, 9, 12], 0),  # tie: strict less-than keeps earliest minimum
]


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
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    fhe.setup(
        {
            "stage": "stage8_5_kms_eval_locate",
            "strict_no_plaintext_fallback": True,
            "operation": "real_tfhe_euint8_argmin_onehot",
            "tie_policy": "first minimum wins by strict less-than update",
            "note": "expected_index is test metadata only; locate is computed by TFHE.",
        }
    )

    print("=== Stage-8.5 KMS TFHE eval_locate / one-hot argmin ===")

    for values, expected_index in CASES:
        encrypted_values = [encrypt_u8(fhe, value) for value in values]

        onehot = fhe.eval_locate(
            encrypted_values,
            expected_index=expected_index,
        )

        user_bits = [fhe.user_decrypt_scalar(flag) for flag in onehot]
        public_bits = [fhe.public_decrypt_scalar(flag) for flag in onehot]

        expected_bits = [1 if idx == expected_index else 0 for idx in range(len(values))]

        print(
            f"values={values} => "
            f"user={user_bits}, public={public_bits}, expected={expected_bits}"
        )

        assert user_bits == expected_bits
        assert public_bits == expected_bits
        assert sum(user_bits) == 1
        assert sum(public_bits) == 1

    print("\nStage-8.5 KMS TFHE eval_locate check passed.")


if __name__ == "__main__":
    main()
