from __future__ import annotations

import time
from pprint import pprint

from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def build_demo_participants() -> list[Participant]:
    return [
        Participant(participant_id="P1", stake_value=100),
        Participant(participant_id="P2", stake_value=250),
        Participant(participant_id="P3", stake_value=175),
    ]


def main() -> None:
    """
    只统计阶段3耗时。
    阶段1、阶段2仅用于准备输入，不计入本阶段时间。
    """
    initialization_result = run_phase1_initialization(security_parameter=128)
    pp = initialization_result["public_parameters"]

    participants = build_demo_participants()
    phase2_result = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=2,
    )

    start = time.perf_counter()
    phase3_result = run_phase3_candidacy(
        pp=pp,
        participants=participants,
        phase2_result=phase2_result,
        proof_share_count=3,
    )
    end = time.perf_counter()

    print("=== Stage 3: Candidate Message Construction ===")
    print(f"Stage 3 Time: {end - start:.6f} seconds")
    print()

    print("[Candidate Messages]")
    pprint(phase3_result.candidate_messages)
    print()

    print("[Participant Artifacts]")
    pprint(phase3_result.participant_artifacts)


if __name__ == "__main__":
    main()