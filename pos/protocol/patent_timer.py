from __future__ import annotations

import csv
import json
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any, Iterator, Mapping


PATENT_STEP_NAMES: tuple[str, ...] = (
    "Step0_public_parameter_setup",
    "Step1_pedersen_commit",
    "Step2_kms_threshold_key_setup",
    "Step3_seed_generation",
    "Step4_kh_prf_share",
    "Step5_encrypt_prf_and_proof",
    "Step6_encrypt_stake_and_proof",
    "Step7_ticket_hash_encrypt_suffix",
    "Step8_candidate_message_build",
    "Step9_verification_seed",
    "Step10_cut_and_choose_open",
    "Step11_proof_verify",
    "Step12_homomorphic_sum_stakes",
    "Step13_total_stake_partial_decrypt",
    "Step14_total_stake_recover",
    "Step15_scaling_ratio",
    "Step16_homomorphic_sum_prf",
    "Step17_homomorphic_scale_prf",
    "Step18_compare_locate_select",
    "Step19_ticket_threshold_decrypt",
    "Step20_ticket_suffix_recover",
    "Step21_winner_observe",
    "Step22_winner_reveal",
    "Step23_public_verify",
)


PATENT_PHASE_STEPS: Mapping[str, tuple[str, ...]] = OrderedDict(
    {
        "Phase1_setup": (
            "Step0_public_parameter_setup",
        ),
        "Phase2_preparation": (
            "Step1_pedersen_commit",
            "Step2_kms_threshold_key_setup",
            "Step3_seed_generation",
        ),
        "Phase3_candidacy": (
            "Step4_kh_prf_share",
            "Step5_encrypt_prf_and_proof",
            "Step6_encrypt_stake_and_proof",
            "Step7_ticket_hash_encrypt_suffix",
            "Step8_candidate_message_build",
        ),
        "Phase4_election": (
            "Step9_verification_seed",
            "Step10_cut_and_choose_open",
            "Step11_proof_verify",
            "Step12_homomorphic_sum_stakes",
            "Step13_total_stake_partial_decrypt",
            "Step14_total_stake_recover",
            "Step15_scaling_ratio",
            "Step16_homomorphic_sum_prf",
            "Step17_homomorphic_scale_prf",
            "Step18_compare_locate_select",
        ),
        "Phase5_reveal": (
            "Step19_ticket_threshold_decrypt",
            "Step20_ticket_suffix_recover",
            "Step21_winner_observe",
            "Step22_winner_reveal",
            "Step23_public_verify",
        ),
    }
)


@dataclass(frozen=True)
class PatentStepEvent:
    step_name: str
    seconds: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatentTimingReport:
    """
    Step-level timer for the final patent protocol path.

    Design rules:
      - This module only measures time.
      - It must not decrypt ciphertexts.
      - It must not inspect encoded_value.
      - It must not provide expected_result or expected_index.
      - It is safe to use around real KMS/TFHE/RLWE calls.
    """

    run_id: str = "single-run"
    participant_count: int | None = None
    threshold: int | None = None
    proof_share_count: int | None = None
    strict_kms: bool = True
    step_seconds: dict[str, float] = field(default_factory=dict)
    step_counts: dict[str, int] = field(default_factory=dict)
    events: list[PatentStepEvent] = field(default_factory=list)

    @contextmanager
    def step(
        self,
        step_name: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> Iterator[None]:
        self.assert_known_step(step_name)
        start = perf_counter()
        try:
            yield
        finally:
            elapsed = perf_counter() - start
            self.add_step_time(
                step_name=step_name,
                seconds=elapsed,
                metadata=dict(metadata or {}),
            )

    def add_step_time(
        self,
        *,
        step_name: str,
        seconds: float,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.assert_known_step(step_name)
        if seconds < 0:
            raise ValueError(f"step seconds must be non-negative, got {seconds}")

        self.step_seconds[step_name] = self.step_seconds.get(step_name, 0.0) + float(seconds)
        self.step_counts[step_name] = self.step_counts.get(step_name, 0) + 1
        self.events.append(
            PatentStepEvent(
                step_name=step_name,
                seconds=float(seconds),
                metadata=dict(metadata or {}),
            )
        )

    def phase_seconds(self) -> dict[str, float]:
        return {
            phase_name: sum(self.step_seconds.get(step_name, 0.0) for step_name in step_names)
            for phase_name, step_names in PATENT_PHASE_STEPS.items()
        }

    def total_seconds(self) -> float:
        return sum(self.step_seconds.values())

    def missing_steps(self) -> list[str]:
        return [step_name for step_name in PATENT_STEP_NAMES if step_name not in self.step_seconds]

    def require_all_steps_recorded(self) -> None:
        missing = self.missing_steps()
        if missing:
            raise AssertionError(
                "Patent timing report is incomplete; missing steps: "
                + ", ".join(missing)
            )

    def to_step_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for step_name in PATENT_STEP_NAMES:
            rows.append(
                {
                    "run_id": self.run_id,
                    "participant_count": self.participant_count,
                    "threshold": self.threshold,
                    "proof_share_count": self.proof_share_count,
                    "strict_kms": self.strict_kms,
                    "step_name": step_name,
                    "seconds": self.step_seconds.get(step_name, 0.0),
                    "count": self.step_counts.get(step_name, 0),
                }
            )
        return rows

    def to_phase_rows(self) -> list[dict[str, Any]]:
        phase_values = self.phase_seconds()
        return [
            {
                "run_id": self.run_id,
                "participant_count": self.participant_count,
                "threshold": self.threshold,
                "proof_share_count": self.proof_share_count,
                "strict_kms": self.strict_kms,
                "phase_name": phase_name,
                "seconds": seconds,
            }
            for phase_name, seconds in phase_values.items()
        ]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "participant_count": self.participant_count,
            "threshold": self.threshold,
            "proof_share_count": self.proof_share_count,
            "strict_kms": self.strict_kms,
            "step_seconds": dict(self.step_seconds),
            "step_counts": dict(self.step_counts),
            "phase_seconds": self.phase_seconds(),
            "total_seconds": self.total_seconds(),
            "missing_steps": self.missing_steps(),
            "events": [
                {
                    "step_name": event.step_name,
                    "seconds": event.seconds,
                    "metadata": event.metadata,
                }
                for event in self.events
            ],
        }

    def write_json(self, path: str | Path) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(self.to_json_dict(), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def write_step_csv(self, path: str | Path) -> None:
        self._write_csv(path=path, rows=self.to_step_rows())

    def write_phase_csv(self, path: str | Path) -> None:
        self._write_csv(path=path, rows=self.to_phase_rows())

    @staticmethod
    def _write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not rows:
            output_path.write_text("", encoding="utf-8")
            return

        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def assert_known_step(step_name: str) -> None:
        if step_name not in PATENT_STEP_NAMES:
            raise ValueError(
                f"Unknown patent step name: {step_name!r}. "
                f"Allowed names: {', '.join(PATENT_STEP_NAMES)}"
            )


def canonical_patent_step_names() -> tuple[str, ...]:
    return PATENT_STEP_NAMES


def canonical_patent_phase_steps() -> Mapping[str, tuple[str, ...]]:
    return PATENT_PHASE_STEPS
