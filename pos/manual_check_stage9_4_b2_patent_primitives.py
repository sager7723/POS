from __future__ import annotations

import os

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache


def encrypt_u8(fhe, value: int):
    return fhe.encrypt_scalar(
        value,
        data_type="euint8",
        no_compression=True,
        no_precompute_sns=True,
    )


def select_by_onehot(fhe, onehot, values, expected_index: int, expected_values: list[int]):
    selected = values[0]
    selected_expected = expected_values[0]

    for idx in range(1, len(values)):
        if idx == expected_index:
            selected_expected = expected_values[idx]

        selected = fhe.eval_select(
            onehot[idx],
            values[idx],
            selected,
            expected_result=selected_expected,
        )

    return selected


def main() -> None:
    os.environ["POS_FHE_BACKEND"] = "kms-threshold"
    os.environ["POS_STRICT_PATENT_MODE"] = "1"

    reset_fhe_backend_cache()

    fhe = initialize_fhe_backend(
        participant_ids=["P1", "P2", "P3"],
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    fhe.setup(
        {
            "stage": "stage9_4_b2_patent_primitives",
            "strict_no_plaintext_fallback": True,
            "operation": "patent_step18_primitives_add_compare_locate_select",
        }
    )

    stakes = [10, 20, 30]
    random_value = 15
    ticket_values = [101, 202, 77]
    expected_index = 1

    stake_cts = [encrypt_u8(fhe, value) for value in stakes]
    random_ct = encrypt_u8(fhe, random_value)

    cumulative_cts = [stake_cts[0]]
    cumulative_expected = [stakes[0]]

    running_ct = stake_cts[0]
    running_plain = stakes[0]

    for idx in range(1, len(stake_cts)):
        running_plain = (running_plain + stakes[idx]) % 256
        running_ct = fhe.eval_add(
            running_ct,
            stake_cts[idx],
            expected_result=running_plain,
        )
        cumulative_cts.append(running_ct)
        cumulative_expected.append(running_plain)

    compare_bits = []
    compare_expected = []
    for cumulative_plain, cumulative_ct in zip(cumulative_expected, cumulative_cts):
        expected = random_value < cumulative_plain
        compare_expected.append(1 if expected else 0)
        compare_bits.append(
            fhe.eval_compare(
                random_ct,
                cumulative_ct,
                expected_result=expected,
            )
        )

    onehot = fhe.eval_locate_first_true(
        compare_bits,
        expected_index=expected_index,
    )

    ticket_cts = [encrypt_u8(fhe, value) for value in ticket_values]
    selected_ticket = select_by_onehot(
        fhe,
        onehot,
        ticket_cts,
        expected_index=expected_index,
        expected_values=ticket_values,
    )

    cumulative_user = [fhe.user_decrypt_scalar(ct) for ct in cumulative_cts]
    cumulative_public = [fhe.public_decrypt_scalar(ct) for ct in cumulative_cts]

    compare_user = [fhe.user_decrypt_scalar(flag) for flag in compare_bits]
    compare_public = [fhe.public_decrypt_scalar(flag) for flag in compare_bits]

    onehot_user = [fhe.user_decrypt_scalar(flag) for flag in onehot]
    onehot_public = [fhe.public_decrypt_scalar(flag) for flag in onehot]

    selected_user = fhe.user_decrypt_scalar(selected_ticket)
    selected_public = fhe.public_decrypt_scalar(selected_ticket)

    expected_onehot = [1 if idx == expected_index else 0 for idx in range(len(stakes))]
    expected_ticket = ticket_values[expected_index]

    print("=== Stage-9.4-B2 patent step18 primitives ===")
    print("stakes:", stakes)
    print("random:", random_value)
    print("cumulative_user:", cumulative_user)
    print("cumulative_public:", cumulative_public)
    print("cumulative_expected:", cumulative_expected)
    print("compare_user:", compare_user)
    print("compare_public:", compare_public)
    print("compare_expected:", compare_expected)
    print("onehot_user:", onehot_user)
    print("onehot_public:", onehot_public)
    print("expected_onehot:", expected_onehot)
    print("selected_user:", selected_user)
    print("selected_public:", selected_public)
    print("expected_ticket:", expected_ticket)

    assert cumulative_user == cumulative_expected
    assert cumulative_public == cumulative_expected
    assert compare_user == compare_expected
    assert compare_public == compare_expected
    assert onehot_user == expected_onehot
    assert onehot_public == expected_onehot
    assert selected_user == expected_ticket
    assert selected_public == expected_ticket

    print("\nStage-9.4-B2 patent primitives check passed.")


if __name__ == "__main__":
    main()
