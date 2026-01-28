import pytest

from phsh._hash import Hasher
from phsh.hashers.argon2 import Argon2

@pytest.fixture
def argon2_hasher():
    return Argon2()


def test_hash_init() -> None:
    argon2 = Argon2()
    hasher = Hasher((argon2,()))
    assert hasher is not None
    assert isinstance(hasher, Hasher)

def test_recommend() -> None:
    recommended = Hasher.recommend()
    assert recommended.__class__.__name__ == "Hasher"
    assert recommended._hasher.__class__.__name__ == "Argon2"
    


