from __future__ import annotations

import os

from pos.crypto.backend_policy import BackendPolicyError
from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def main() -> None:
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    print("=== strict mode rejects compatibility backend ===")
    os.environ["POS_FHE_BACKEND"] = "compatibility"
    reset_fhe_backend_cache()

    try:
        initialize_fhe_backend(participant_ids=["P1", "P2", "P3", "P4"])
    except BackendPolicyError as exc:
        print(str(exc))
    else:
        raise AssertionError("strict patent mode must reject compatibility backend")

    print("\n=== strict mode accepts kms-threshold backend ===")
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3", "P4"],
        threshold=1,
    )

    ctx = fhe.setup(
        {
            "stage": "stage7_strict_backend_policy_check",
            "strict_no_plaintext_fallback": True,
        }
    )

    print(ctx.to_dict())

    ciphertext = fhe.encrypt_scalar(7, data_type="euint8")
    user_plaintext = fhe.user_decrypt_scalar(ciphertext)
    public_plaintext = fhe.public_decrypt_scalar(ciphertext)

    print("\n=== strict mode kms-threshold decrypt ===")
    print("user_plaintext:", user_plaintext)
    print("public_plaintext:", public_plaintext)

    assert user_plaintext == 7
    assert public_plaintext == 7

    print("\nStage-7 strict backend policy check passed.")


if __name__ == "__main__":
    main()