from __future__ import annotations

import os

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.patent_fhe import run_patent_fhe_leader_election


PARTICIPANTS = ["P1", "P2", "P3", "P4"]


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    scores = [31, 12, 44, 20]
    expected_index = 1
    expected_bits = [0, 1, 0, 0]

    result = run_patent_fhe_leader_election(
        PARTICIPANTS,
        scores,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
        expected_index_for_test=expected_index,
        decrypt_for_test=True,
        setup_params={
            "stage": "stage9_2_patent_fhe_protocol_entry",
            "strict_no_plaintext_fallback": True,
            "operation": "protocol_level_secret_leader_election",
            "backend": "kms-threshold",
        },
    )

    print("=== Stage-9.2 patent FHE protocol entry ===")
    print("participants:", result.participant_ids)
    print("scores:", scores)
    print("encrypted flags:")
    for row in result.encrypted_winner_flags_json():
        print(row)

    print("test_user_bits:", result.test_user_bits)
    print("test_public_bits:", result.test_public_bits)
    print("expected_bits:", expected_bits)

    assert result.test_user_bits == expected_bits
    assert result.test_public_bits == expected_bits

    print("\\nStage-9.2 patent FHE protocol entry check passed.")


if __name__ == "__main__":
    main()
