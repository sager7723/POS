from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from pos.crypto.fhe import reset_fhe_backend_cache


@pytest.fixture(autouse=True)
def _isolate_fhe_backend_env():
    """
    让测试默认在 compatibility 后端下启动，避免继承外部 shell 里的
    POS_FHE_BACKEND=openfhe 导致普通阶段测试（尤其 test_stage2）误判。

    需要 real OpenFHE 的测试会在测试体内部显式改成 openfhe，
    这个 fixture 不会妨碍它们。
    """
    original_backend = os.environ.get("POS_FHE_BACKEND")

    os.environ["POS_FHE_BACKEND"] = "compatibility"
    reset_fhe_backend_cache()

    try:
        yield
    finally:
        reset_fhe_backend_cache()
        if original_backend is None:
            os.environ.pop("POS_FHE_BACKEND", None)
        else:
            os.environ["POS_FHE_BACKEND"] = original_backend