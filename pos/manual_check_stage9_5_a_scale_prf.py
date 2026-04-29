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
            "stage": "stage9_5_a_scale_prf",
            "strict_no_plaintext_fallback": True,
            "operation": "patent_step17_scale_prf_ciphertext",
        }
    )

    prf_plain = 128
    total_stake = 60
    prf_modulus = 256
    expected_scaled = (prf_plain * total_stake) // prf_modulus

    prf_ct = encrypt_u8(fhe, prf_plain)

    scaled_ct = fhe.eval_scale_prf(
        prf_ct,
        numerator=total_stake,
        denominator=prf_modulus,
        expected_result=expected_scaled,
    )

    user_plain = fhe.user_decrypt_scalar(scaled_ct)
    public_plain = fhe.public_decrypt_scalar(scaled_ct)

    print("=== Stage-9.5-A patent scale PRF ===")
    print("prf_plain:", prf_plain)
    print("total_stake:", total_stake)
    print("prf_modulus:", prf_modulus)
    print("expected_scaled:", expected_scaled)
    print("user_plain:", user_plain)
    print("public_plain:", public_plain)

    assert user_plain == expected_scaled
    assert public_plain == expected_scaled

    print("\\nStage-9.5-A patent scale PRF check passed.")


if __name__ == "__main__":
    main()
