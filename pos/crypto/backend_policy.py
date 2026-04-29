from __future__ import annotations

import os


class BackendPolicyError(RuntimeError):
    pass


STRICT_PATENT_ENV = "POS_STRICT_PATENT_MODE"
FHE_BACKEND_ENV = "POS_FHE_BACKEND"


_ALLOWED_STRICT_BACKENDS = {
    "kms-threshold",
    "thfhe",
    "openfhe-replacement",
}


_FORBIDDEN_STRICT_BACKENDS = {
    "",
    "compatibility",
    "compatible",
    "mock",
    "dummy",
    "test",
    "plaintext",
    "inmemory",
    "in-memory",
}


def normalize_backend_name(name: str | None) -> str:
    return (name or "").strip().lower().replace("_", "-")


def strict_patent_mode_enabled() -> bool:
    value = os.environ.get(STRICT_PATENT_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on", "strict"}


def assert_backend_allowed_for_strict_patent_mode(backend_name: str | None = None) -> None:
    """
    Enforce final patent-mode backend selection.

    In strict mode, compatibility/mock/plaintext backends are forbidden.
    This function does not make incomplete KMS eval operations magically valid;
    it only prevents accidental fallback to non-patent placeholder backends.
    """
    if not strict_patent_mode_enabled():
        return

    normalized = normalize_backend_name(
        backend_name if backend_name is not None else os.environ.get(FHE_BACKEND_ENV)
    )

    if normalized in _FORBIDDEN_STRICT_BACKENDS:
        raise BackendPolicyError(
            f"{STRICT_PATENT_ENV}=1 forbids POS_FHE_BACKEND={normalized!r}. "
            "Use one of: "
            + ", ".join(sorted(_ALLOWED_STRICT_BACKENDS))
            + "."
        )

    if normalized not in _ALLOWED_STRICT_BACKENDS:
        raise BackendPolicyError(
            f"{STRICT_PATENT_ENV}=1 does not allow unknown backend {normalized!r}. "
            "Use one of: "
            + ", ".join(sorted(_ALLOWED_STRICT_BACKENDS))
            + "."
        )