from __future__ import annotations

import time
from pprint import pprint

from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def build_demo_participants() -> list[Participant]:
    """
    第二阶段测试输入
    """
    return [
        Participant(participant_id="P1", stake_value=100),
        Participant(participant_id="P2", stake_value=250),
        Participant(participant_id="P3", stake_value=175),
    ]


def main() -> None:
    """
    Stage2：
    - 只测试阶段2运行时间
    - 阶段1仅用于提供输入（不计入时间）
    """

    # ⚠️ 初始化（不计入时间）
    initialization_result = run_phase1_initialization(security_parameter=128)
    pp = initialization_result["public_parameters"]

    participants = build_demo_participants()
    threshold = 2

    # ✅ 只计阶段2
    start = time.perf_counter()

    phase2_result = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=threshold,
    )

    end = time.perf_counter()

    print("=== Stage 2: Preparation ===")
    print(f"Stage 2 Time: {end - start:.6f} seconds")
    print()

    print("[Inputs]")
    pprint(participants)
    print()

    print("[Outputs]")
    pprint(phase2_result)


if __name__ == "__main__":
    main()