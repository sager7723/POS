# 选举进行10000次，然后计算得出每个阶段以及总过程的平均耗时，并且根据P1\P2\P3获胜的次数绘制扇形图
import time
import matplotlib.pyplot as plt
from collections import defaultdict

from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.reveal import run_phase5_reveal


def build_participants():
    return [
        Participant("P1", 100),
        Participant("P2", 200),
        Participant("P3", 300),
    ]


def main():
    NUM_RUNS = 10000

    participants = build_participants()

    # 时间统计
    total_time_stage1 = 0
    total_time_stage2 = 0
    total_time_stage3 = 0
    total_time_stage4 = 0
    total_time_stage5 = 0
    total_time_all = 0

    # 胜者统计
    winner_count = defaultdict(int)

    for _ in range(NUM_RUNS):
        round_start = time.perf_counter()

        # =====================
        # Stage 1
        # =====================
        start1 = time.perf_counter()
        init = run_phase1_initialization()
        end1 = time.perf_counter()

        pp = init["public_parameters"]

        # =====================
        # Stage 2
        # =====================
        start2 = time.perf_counter()
        phase2 = run_phase2_preparation(pp, participants, threshold=2)
        end2 = time.perf_counter()

        # =====================
        # Stage 3
        # =====================
        start3 = time.perf_counter()
        phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)
        end3 = time.perf_counter()

        # =====================
        # Stage 4
        # =====================
        start4 = time.perf_counter()
        phase4 = run_phase4_election(phase3.candidate_messages)
        end4 = time.perf_counter()

        # =====================
        # Stage 5
        # =====================
        start5 = time.perf_counter()
        phase5 = run_phase5_reveal(
            phase3.candidate_messages,
            phase4.winning_ticket_ciphertext,
        )
        end5 = time.perf_counter()

        round_end = time.perf_counter()

        # 累加时间
        total_time_stage1 += (end1 - start1)
        total_time_stage2 += (end2 - start2)
        total_time_stage3 += (end3 - start3)
        total_time_stage4 += (end4 - start4)
        total_time_stage5 += (end5 - start5)
        total_time_all += (round_end - round_start)

        # 统计赢家
        winner_count[phase5.winner_id] += 1

    # =====================
    # 平均时间
    # =====================
    print("\n=== AVERAGE TIMING (over 10000 runs) ===")
    print(f"Stage 1 Avg: {total_time_stage1 / NUM_RUNS:.6f}s")
    print(f"Stage 2 Avg: {total_time_stage2 / NUM_RUNS:.6f}s")
    print(f"Stage 3 Avg: {total_time_stage3 / NUM_RUNS:.6f}s")
    print(f"Stage 4 Avg: {total_time_stage4 / NUM_RUNS:.6f}s")
    print(f"Stage 5 Avg: {total_time_stage5 / NUM_RUNS:.6f}s")
    print(f"Total Avg:   {total_time_all / NUM_RUNS:.6f}s")

    # =====================
    # 胜率统计
    # =====================
    print("\n=== WINNER DISTRIBUTION ===")
    for k, v in winner_count.items():
        print(f"{k}: {v} ({v / NUM_RUNS:.2%})")

    # =====================
    # 画饼图
    # =====================
    labels = list(winner_count.keys())
    sizes = list(winner_count.values())

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.2f%%')
    plt.title("Winner Distribution")
    plt.show()


if __name__ == "__main__":
    main()