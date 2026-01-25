
try:
    import argon2.exceptions
    from argon2 import PasswordHasher
except ImportError as e:
    from ..exceptions import HasherNotFound
    raise HasherNotFound("argon2") from e

class Argon2():

