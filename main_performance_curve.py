# 选举人数从3增加到1000，所有人权重相同，对于每一回的选举人数进行100轮选举，得出各阶段平均时间和总平均时间，并生成性能曲线
import time
import matplotlib.pyplot as plt

from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.reveal import run_phase5_reveal


# =========================
# 构造参与者
# =========================
def build_participants(n):
    return [Participant(f"P{i+1}", 100) for i in range(n)]


# =========================
# 单规模测试
# =========================
def run_experiment(num_participants, rounds=100):

    participants = build_participants(num_participants)

    total_s1 = total_s2 = total_s3 = total_s4 = total_s5 = total_all = 0

    for _ in range(rounds):

        round_start = time.perf_counter()

        # Stage1
        t1 = time.perf_counter()
        init = run_phase1_initialization()
        t2 = time.perf_counter()
        pp = init["public_parameters"]

        # Stage2
        t3 = time.perf_counter()
        phase2 = run_phase2_preparation(pp, participants, threshold=3)
        t4 = time.perf_counter()

        # Stage3
        t5 = time.perf_counter()
        phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)
        t6 = time.perf_counter()

        # Stage4
        t7 = time.perf_counter()
        phase4 = run_phase4_election(phase3.candidate_messages)
        t8 = time.perf_counter()

        # Stage5
        t9 = time.perf_counter()
        run_phase5_reveal(
            phase3.candidate_messages,
            phase4.winning_ticket_ciphertext,
        )
        t10 = time.perf_counter()

        round_end = time.perf_counter()

        total_s1 += (t2 - t1)
        total_s2 += (t4 - t3)
        total_s3 += (t6 - t5)
        total_s4 += (t8 - t7)
        total_s5 += (t10 - t9)
        total_all += (round_end - round_start)

    return {
        "s1": total_s1 / rounds,
        "s2": total_s2 / rounds,
        "s3": total_s3 / rounds,
        "s4": total_s4 / rounds,
        "s5": total_s5 / rounds,
        "total": total_all / rounds,
    }


# =========================
# 主实验
# =========================
def main():

    # ✅ 每隔10人测试一次
    scales = list(range(10, 1001, 10))

    s1_list = []
    s2_list = []
    s3_list = []
    s4_list = []
    s5_list = []
    total_list = []

    for n in scales:
        print(f"Running n = {n}")

        result = run_experiment(n, rounds=100)

        s1_list.append(result["s1"])
        s2_list.append(result["s2"])
        s3_list.append(result["s3"])
        s4_list.append(result["s4"])
        s5_list.append(result["s5"])
        total_list.append(result["total"])

        print(f"  Total Avg Time: {result['total']:.6f}s")

    # =========================
    # 绘图
    # =========================
    plt.figure(figsize=(8, 6))

    plt.plot(scales, total_list, label="Total", linewidth=2)
    plt.plot(scales, s3_list, label="Stage3", linestyle="--")

    plt.xlabel("Number of Participants")
    plt.ylabel("Average Time (seconds)")
    plt.title("Protocol Performance Scaling (step=10)")

    plt.legend()
    plt.grid()

    plt.show()


if __name__ == "__main__":
    main()