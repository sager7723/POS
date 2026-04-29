from __future__ import annotations

import os
from types import SimpleNamespace

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.protocol.patent_phase4 import run_phase4_patent_complete_election


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

    participant_ids = ["P1", "P2", "P3"]

    fhe = initialize_fhe_backend(
        participant_ids=participant_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )
    fhe.setup(
        {
            "stage": "stage9_5_c_metadata_dependency_guard",
            "strict_no_plaintext_fallback": True,
        }
    )

    candidate_messages = {
        "P1": SimpleNamespace(
            encrypted_stake=encrypt_u8(fhe, 10),
            encrypted_prf_share=encrypt_u8(fhe, 20),
            encrypted_ticket=[encrypt_u8(fhe, 101), encrypt_u8(fhe, 102)],
        ),
        "P2": SimpleNamespace(
            encrypted_stake=encrypt_u8(fhe, 20),
            encrypted_prf_share=encrypt_u8(fhe, 44),
            encrypted_ticket=[encrypt_u8(fhe, 201), encrypt_u8(fhe, 202)],
        ),
        "P3": SimpleNamespace(
            encrypted_stake=encrypt_u8(fhe, 30),
            encrypted_prf_share=encrypt_u8(fhe, 0),
            encrypted_ticket=[encrypt_u8(fhe, 77), encrypt_u8(fhe, 78)],
        ),
    }

    try:
        run_phase4_patent_complete_election(
            candidate_messages,
            threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
            prf_modulus=256,
        )
    except RuntimeError as exc:
        text = str(exc)
        print("=== Stage-9.5-C metadata dependency guard ===")
        print(text)
        assert "metadata-free KMS decrypt" in text
        assert "Do not pass plaintext expected_stakes_for_test in final mode" in text
    else:
        raise AssertionError(
            "strict patent complete phase4 must not silently run with fake metadata"
        )

    print("\\nStage-9.5-C metadata dependency guard check passed.")


if __name__ == "__main__":
    main()
