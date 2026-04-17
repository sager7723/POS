import time
from pprint import pprint

from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election


def build_participants():
    return [
        Participant("P1", 100),
        Participant("P2", 200),
        Participant("P3", 300),
    ]


def main():
    # 准备数据（不计时间）
    pp = run_phase1_initialization()["public_parameters"]
    participants = build_participants()
    phase2 = run_phase2_preparation(pp, participants, threshold=2)
    phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)

    # 只测阶段4
    start = time.perf_counter()

    result = run_phase4_election(phase2, phase3.candidate_messages)

    end = time.perf_counter()

    print("=== Stage 4: Election ===")
    print(f"Stage 4 Time: {end - start:.6f} seconds\n")

    pprint(result)


if __name__ == "__main__":
    main()