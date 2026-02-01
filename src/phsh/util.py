def _validate_str_or_bytes(s: str | bytes) -> None:
    if not isinstance(s, (str, bytes)):
        raise TypeError(f"{type(s).__name__} must be str or bytes")


def _require_str(s: str | bytes, *, encoding: str = "utf-8") -> str:
    return s if isinstance(s, str) else s.decode(encoding)


def _require_bytes(s: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return s if isinstance(s, bytes) else s.encode(encoding)
