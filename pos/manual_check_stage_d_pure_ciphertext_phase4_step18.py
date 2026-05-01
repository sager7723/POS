from __future__ import annotations

import inspect

from pos.protocol.patent_phase4 import (
    _sum_lottery_ciphertexts,
    run_phase4_patent_complete_election,
)
from pos.protocol.patent_step18 import (
    PatentStep18WinnerSelectionResult,
    _select_one_chunk_by_onehot,
    step18_patent_select_winner_ticket,
    step18_patent_select_winner_ticket_from_candidate_messages,
)


FORBIDDEN_PARAMETER_NAMES = {
    "expected_plaintexts_for_test",
    "expected_stakes_for_test",
    "expected_prf_shares_for_test",
    "expected_ticket_chunks_for_test",
    "expected_winner_index_for_test",
    "expected_scaled_random_for_test",
    "expected_result",
    "expected_index",
}


def assert_no_forbidden_parameters(function) -> None:
    signature = inspect.signature(function)
    forbidden = FORBIDDEN_PARAMETER_NAMES.intersection(signature.parameters)
    if forbidden:
        raise AssertionError(
            f"{function.__name__} still exposes forbidden expected/test parameters: "
            + ", ".join(sorted(forbidden))
        )


def main() -> None:
    print("=== Stage D Pure Ciphertext Phase4/Step18 Check ===")

    for function in [
        _sum_lottery_ciphertexts,
        run_phase4_patent_complete_election,
        _select_one_chunk_by_onehot,
        step18_patent_select_winner_ticket,
        step18_patent_select_winner_ticket_from_candidate_messages,
    ]:
        assert_no_forbidden_parameters(function)
        print("signature clean:", function.__name__)

    result_fields = set(PatentStep18WinnerSelectionResult.__dataclass_fields__)
    forbidden_result_fields = {
        "expected_cumulative_stakes",
        "expected_compare_bits",
        "expected_winner_index",
        "expected_winning_ticket_chunks",
    }
    remaining = result_fields.intersection(forbidden_result_fields)
    if remaining:
        raise AssertionError(
            "PatentStep18WinnerSelectionResult still exposes forbidden expected fields: "
            + ", ".join(sorted(remaining))
        )

    print("result dataclass clean:", PatentStep18WinnerSelectionResult.__name__)
    print("Stage D pure ciphertext Phase4/Step18 check passed.")


if __name__ == "__main__":
    main()
