try:
    import argon2.exceptions
    from argon2 import PasswordHasher
    from low_level import Type
except ImportError as e:
    from ..exceptions import HasherNotFound

    raise HasherNotFound("argon2") from e

from .protocol import HasherProtocol
from typing import ClassVar, Type


def _validate_str_or_bytes(s: str | bytes) -> None:
    if not isinstance(s, (str, bytes)):
        raise TypeError(f"{type(s).__name__} must be str or bytes")


def _require_str(s: str | bytes, *, encoding: str = "utf-8") -> str:
    return s if isinstance(s, str) else s.decode(encoding)


def _require_bytes(s: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return s if isinstance(s, bytes) else s.encode(encoding)


class Argon2(HasherProtocol):
    def __init__(
        self,
        time_cost: int = argon2.DEFAULT_TIME_COST,
        memory_cost: int = argon2.DEFAULT_MEMORY_COST,
        parallelism: int = argon2.DEFAULT_PARALLELISM,
        hash_len: int = argon2.DEFAULT_HASH_LENGTH,
        salt_len: int = argon2.DEFAULT_RANDOM_SALT_LENGTH,
        encoding: str = "utf-8",
        type: argon2.Type = argon2.Type.ID,
    ):
        """
        Args:
            These are the recommended default setting for Argon2.
            https://github.com/hynek/argon2-cffi/blob/main/src/argon2/_password_hasher.py
        """
        self._hasher = PasswordHasher(
            time_cost, memory_cost, parallelism, hash_len, salt_len, "utf-8", type
        )

    _header_to_variant: ClassVar[dict[bytes, Type]] = {
        b"$argon2i$": Type.I,
        b"$argon2d$": Type.D,
        b"$argon2id$": Type.ID,
    }

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:
        """
        Determine the variant of the given hash. (Argon2i, Argon2d, or Argon2id).
        This should not be used to validate the entire hash structure or if the hash is properly formed beyond
        checking the variant

        Args:
            hash: str or bytes to examine, if str, it will be converted to bytes using UTF-8 encoding

        Raises:
            UnicodeDecodeError:
                If hash is not str or byte.

        Returns:
            True if the extracted variant from the hash is valid, False otherwise.

        Examples:
            >>> Argon2Hasher.identify('$argon2id$v=19$m=65536,t=3,p=4$...')
            True
            >>> Argon2Hasher.identify('$2b$12$...')  #bcrypt hash
            False
            >>> Argon2Hasher.identify('not a hash')
            False
        """
        try:
            h = _require_bytes(hash)
        except UnicodeDecodeError:
            return False

        for header in cls._header_to_variant.keys():
            if h.startswith(header):
                return True
        return False

    def hash(self, password: str | bytes) -> str:
        _validate_str_or_bytes(password)
        return self._hasher.hash(password)

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        _validate_str_or_bytes(password)
        _validate_str_or_bytes(hash)
        try:
            return self._hasher.verify(password, hash)
        except (
            argon2.exceptions.VerifyMismatchError,
            argon2.exceptions.VerificationError,
            argon2.exceptions.InvalidHashError,
        ):
            return False

    def needs_rehash(self, hash: str | bytes) -> bool:
        return self._hasher.check_needs_rehash(_require_bytes(hash))
