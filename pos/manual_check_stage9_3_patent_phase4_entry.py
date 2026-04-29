from __future__ import annotations

import os

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.protocol.patent_election import run_phase4_patent_fhe_election


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    candidate_messages = {
        "P1": {"candidate": "P1"},
        "P2": {"candidate": "P2"},
        "P3": {"candidate": "P3"},
        "P4": {"candidate": "P4"},
    }

    scores = [42, 19, 77, 35]
    expected_index = 1
    expected_bits = [0, 1, 0, 0]

    result = run_phase4_patent_fhe_election(
        candidate_messages,
        scores,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
        expected_index_for_test=expected_index,
        decrypt_for_test=True,
    )

    print("=== Stage-9.3 patent Phase-4 FHE election entry ===")
    print("participant_ids:", result.participant_ids)
    print("scores:", scores)
    print("encrypted winner flags:")
    for row in result.encrypted_winner_flags_json():
        print(row)

    print("test_user_bits:", result.test_user_bits)
    print("test_public_bits:", result.test_public_bits)
    print("expected_bits:", expected_bits)

    assert result.participant_ids == ["P1", "P2", "P3", "P4"]
    assert result.test_user_bits == expected_bits
    assert result.test_public_bits == expected_bits

    print("\nStage-9.3 patent Phase-4 FHE election entry check passed.")


if __name__ == "__main__":
    main()
