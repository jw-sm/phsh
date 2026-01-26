import pytest
from phsh.hashers.argon2 import Argon2 


_PASSWORD = "phsh_hashing_util"
_HASH = Argon2()
_HASHED_PASSWORD_STR = _HASH.hash(_PASSWORD)
_HASHED_PASSWORD_BYTES = _HASHED_PASSWORD_STR.encode("utf-8")

# Note: This was generated using the C reference
# echo -n "phsh_hashing_util" | ./argon2 somesalt -id -m 16 -t 3 -p 4 -l 32
# Type:           Argon2id
# Iterations:     3
# Memory:         65536 KiB
# Parallelism:    4
# Hash:           0e28873b4ac25cf4ca68cd7799a7a00b510434abc7f67815b1cbaec2c475124a
# Encoded:        $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$DiiHO0rCXPTKaM13maegC1EENKvH9ngVscuuwsR1Eko
# 0.201 seconds
# Verification ok

# Argon2 CLI Parameters
# echo -n "phsh_hashing_util" | ./argon2 somesalt -id -m 16 -t 3 -p 4 -l 32
#
# -id : Argon2id variant
# -m  : Memory cost as 2^N KiB (e.g., -m 16 = 64 MiB)
# -t  : Time cost / iterations (e.g., -t 3 = 3 passes)
# -p  : Parallelism / threads (e.g., -p 4 = 4 threads)
# -l  : Hash length in bytes (e.g., -l 32 = 256 bits)
#
# Output: $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$DiiHO0rCXPTKaM13maegC1EENKvH9ngVscuuwsR1Eko

ARGON2ID_HASH_STR: str = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$DiiHO0rCXPTKaM13maegC1EENKvH9ngVscuuwsR1Eko"

@pytest.fixture
def argon2() -> Argon2:
    return Argon2()

@pytest.mark.parametrize(
    "password",
    [
        pytest.param(_PASSWORD, id="standard_password"),
        pytest.param("", id="empty_password"),
        pytest.param("a" * 100, id="long_password"),
    ],
)

def test_hash(password: str, argon2: Argon2Hasher) -> None:
    print(f"\n→ Hashing: '{password[:20]}...'")
    hashed = argon2.hash(password)
    print(f"→ Result: {hashed}...")
    assert isinstance(hashed, str)

@pytest.mark.parametrize(
    "hash,password,result",
    [
        pytest.param(_HASHED_PASSWORD_STR, _PASSWORD, True, id="correct_password"),
        pytest.param(_HASHED_PASSWORD_STR, "INCORRECTPASSWORD", False, id="incorrect_password"),
    ],
)
def test_verify(
    hash: str | bytes, password: str, result: bool, argon2: Argon2Hasher
) -> None:
    print(f"\n→ Verifying: hash={hash[:20]}... password='{password}' expected={result}")
    assert argon2.verify(hash, password) == result
