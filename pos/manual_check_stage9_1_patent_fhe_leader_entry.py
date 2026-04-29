from __future__ import annotations

import os

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.patent_fhe import PatentFheLeaderElection


PARTICIPANTS = ["P1", "P2", "P3", "P4"]

CASES = [
    {
        "scores": [13, 7, 22, 9],
        "expected_index": 1,
        "expected_leader": "P2",
    },
    {
        "scores": [7, 7, 9, 12],
        "expected_index": 0,
        "expected_leader": "P1",
    },
]


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    election = PatentFheLeaderElection(
        PARTICIPANTS,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
        setup_params={
            "stage": "stage9_1_patent_fhe_leader_entry",
            "strict_no_plaintext_fallback": True,
            "operation": "patent_secret_leader_election_argmin_onehot",
            "backend": "kms-threshold",
        },
    )

    print("=== Stage-9.1 patent FHE leader election entry ===")

    for case in CASES:
        scores = case["scores"]
        expected_index = case["expected_index"]
        expected_leader = case["expected_leader"]

        result = election.elect_from_plain_scores_for_test(
            scores,
            expected_index=expected_index,
        )

        user_bits, public_bits = election.decrypt_onehot_for_test(result)

        expected_bits = [
            1 if idx == expected_index else 0
            for idx in range(len(PARTICIPANTS))
        ]

        user_leader = PARTICIPANTS[user_bits.index(1)]
        public_leader = PARTICIPANTS[public_bits.index(1)]

        print(
            f"scores={scores} => "
            f"user_bits={user_bits}, public_bits={public_bits}, "
            f"user_leader={user_leader}, public_leader={public_leader}, "
            f"expected={expected_leader}"
        )

        assert user_bits == expected_bits
        assert public_bits == expected_bits
        assert user_leader == expected_leader
        assert public_leader == expected_leader

    print("\nStage-9.1 patent FHE leader election entry check passed.")


if __name__ == "__main__":
    main()
