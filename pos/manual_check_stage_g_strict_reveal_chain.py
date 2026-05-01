from __future__ import annotations

import inspect
from pathlib import Path

from pos.protocol import patent_step20, reveal


FORBIDDEN_SOURCE_TOKENS = {
    "expected_winner_index",
    "winner_index_for_test",
    "expected_winner",
    "decrypt_all",
    "all_ticket",
    "all_tickets",
    "user_decrypt_scalar",
    "encoded_value",
    "metadata.noise",
}


def function_source(function) -> str:
    return inspect.getsource(function)


def main() -> None:
    print("=== Stage G Strict Reveal Chain Check ===")

    target_paths = [
        Path("pos/protocol/patent_step20.py"),
        Path("pos/protocol/reveal.py"),
    ]

    for path in target_paths:
        source = path.read_text(encoding="utf-8")
        remaining = sorted(token for token in FORBIDDEN_SOURCE_TOKENS if token in source)
        if remaining:
            raise AssertionError(f"{path} contains forbidden tokens: {remaining}")
        print("source forbidden-token clean:", path)

    patent_step19_src = function_source(
        patent_step20.step19_generate_winning_ticket_decryption_shares
    )
    patent_step20_src = function_source(
        patent_step20.step20_recover_winning_ticket_chunks
    )

    if "winning_ticket_ciphertext" not in patent_step19_src:
        raise AssertionError("patent_step20 Step19 must operate on winning_ticket_ciphertext")
    if "decrypt_share" not in patent_step19_src:
        raise AssertionError("patent_step20 Step19 must call decrypt_share")
    if "fhe.decrypt(" not in patent_step20_src:
        raise AssertionError("patent_step20 Step20 must combine shares with fhe.decrypt")
    if "user_decrypt_scalar" in patent_step19_src + patent_step20_src:
        raise AssertionError("patent_step20 Step19/20 must not use user_decrypt_scalar")

    reveal_step19_src = function_source(reveal.step19_generate_decryption_shares)
    reveal_step20_src = function_source(reveal.step20_recover_ticket_suffix)
    reveal_step23_src = function_source(reveal.step23_verify_winner)
    run_phase5_src = function_source(reveal.run_phase5_reveal)

    if "winning_ticket_ciphertext" not in reveal_step19_src:
        raise AssertionError("reveal Step19 must operate on winning_ticket_ciphertext")
    if "decrypt_share" not in reveal_step19_src:
        raise AssertionError("reveal Step19 must call decrypt_share")
    if "fhe.decrypt(" not in reveal_step20_src:
        raise AssertionError("reveal Step20 must combine shares with fhe.decrypt")
    if "ticket_artifact.ticket_hash_suffix" in reveal_step23_src:
        raise AssertionError(
            "Step23 public verification must not read local ticket hash suffix artifacts"
        )
    if "strict reveal requires phase4_result" not in run_phase5_src:
        raise AssertionError("strict run_phase5_reveal must require phase4_result")

    print("Step19 uses partial decrypt shares only on winning_ticket_ciphertext")
    print("Step20 combines shares only for winning_ticket_ciphertext")
    print("Step23 public verification avoids local suffix oracle")
    print("Stage G strict reveal chain check passed.")


if __name__ == "__main__":
    main()
