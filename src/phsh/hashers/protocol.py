import typing


class HasherProtocol(typing.Protocol):
    @classmethod
    def identify(cls, hash: str | bytes) -> bool: ...

    def hash(self, password: str | bytes) -> str: ...

    def verify(self, password: str | bytes, hash: str | bytes) -> bool: ...

    def needs_rehash(self, hash: str | bytes) -> bool: ...


__all__ = ["HasherProtocol"]
