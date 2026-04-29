from __future__ import annotations

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def main() -> None:
    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(participant_ids=["P1", "P2", "P3"])
    fhe.setup(
        {
            "backend_name": "thfhe",
            "threshold": 2,
            "participant_ids": ["P1", "P2", "P3"],
            "params": {
                "stage": "stage2_compare_select_check",
            },
        }
    )

    # random = 25, prefix stakes = [10, 30, 60]
    random_ct = fhe.encrypt_scalar(25)
    s1 = fhe.encrypt_scalar(10)
    s2 = fhe.encrypt_scalar(30)
    s3 = fhe.encrypt_scalar(60)

    compare_bits = fhe.eval_compare(random_ct, [s1, s2, s3])
    print("compare bits:")
    for i, bit in enumerate(compare_bits):
        print(i, bit.payload)

    locator_bits = fhe.eval_locate(compare_bits)
    print("\nlocator bits:")
    for i, bit in enumerate(locator_bits):
        print(i, bit.payload)

    t1 = fhe.encrypt_scalar(1111)
    t2 = fhe.encrypt_scalar(2222)
    t3 = fhe.encrypt_scalar(3333)

    selected = fhe.eval_select(locator_bits, [t1, t2, t3])
    print("\nselected:")
    print(selected.payload)

    assert len(compare_bits) == 3
    assert len(locator_bits) == 3
    assert selected.backend == "thfhe"

    print("\nStage-2 compare/locate/select bridge check passed.")


if __name__ == "__main__":
    main()