from .hashers.protocol import HasherProtocol
from collections.abc import Sequence


class Hasher:
    def __init__(self, hashers: Sequence[HasherProtocol]) -> None:
        assert len(hashers) > 0, "Include at least one valid hasher."
        self.hashers = hashers
        self._hasher = hashers[0]

    @classmethod
    def recommend(cls) -> "Hasher":
        from .hashers.argon2 import Argon2
        return cls((Argon2(),))
