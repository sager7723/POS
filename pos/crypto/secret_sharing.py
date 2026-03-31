from typing import List, Any


class MockSecretSharing:

    def share_secret(self, secret: Any, n: int) -> List[Any]:
        return [f"share_{i}" for i in range(n)]

    def recover_secret(self, shares: List[Any]) -> Any:
        return "recovered_secret"

    def recover_secret_in_exponent(self, shares: List[Any]) -> Any:
        return "recovered_secret_exp"