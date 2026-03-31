import time
from pos.protocol.initialization import run_phase1_initialization


def main():
    start = time.perf_counter()

    result = run_phase1_initialization()

    end = time.perf_counter()

    print("=== Stage 1: Initialization ===")
    print(f"Time: {end - start:.6f} seconds")
    print(result)


if __name__ == "__main__":
    main()