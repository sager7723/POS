from __future__ import annotations

import os

from pos.protocol.election import run_phase4_election


def main() -> None:
    os.environ["POS_STRICT_PATENT_MODE"] = "1"
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"

    try:
        run_phase4_election(
            phase2_result=None,  # type: ignore[arg-type]
            candidate_messages={"P1": object()},  # type: ignore[dict-item]
        )
    except RuntimeError as exc:
        text = str(exc)
        print("=== strict patent mode legacy guard ===")
        print(text)
        assert "forbids the legacy run_phase4_election path" in text
        assert "Ccompare" in text
        assert "Clocate" in text
        assert "Cselect" in text
    else:
        raise AssertionError("strict patent mode must not allow legacy run_phase4_election")

    print("\nStage-9.4-A strict legacy guard check passed.")


if __name__ == "__main__":
    main()
