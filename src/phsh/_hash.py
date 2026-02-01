from .hashers.protocol import HasherProtocol
from collections.abc import Sequence
from .util import _validate_str_or_bytes
from .exceptions import UnknownHashError


class Hasher:
    def __init__(self, hashers: Sequence[HasherProtocol]) -> None:
        assert len(hashers) > 0, "Include at least one supported hasher."
        self.hashers = hashers
        self.active_hasher = hashers[0]

    @classmethod
    def recommend(cls) -> "Hasher":
        from .hashers.argon2 import Argon2

        return cls((Argon2(),))

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        return self.active__hasher.hash(password, salt=salt)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        _validate_str_or_bytes(password)
        _validate_str_or_bytes(hash)
        for hasher in self.hashers:
            if hasher.identify(hash):
                return hasher.verify(password, hash)
        raise UnknownHashError()
