import argon2
from dataclasses import dataclass


@dataclass
class Argon2Hash:
    argon_variant: str
    version: str
    salt: str
    digest: str


def hash_passphrase(passphrase: str) -> str:
    ph = argon2.PasswordHasher()
    try:
        hash = ph.hash(passphrase)
    except argon2.exceptions.HashinError as err:
        print("Failed to hash passphrase: ", err)
        raise

    return hash


def parse_argon2_hash(argon2_hash: str) -> Argon2Hash:
    tokens = argon2_hash.split('$')
    tokens = [token for token in tokens if len(token) != 0]

    argon_variant = tokens[0]
    version = tokens[1].strip('v=')
    salt = tokens[3]
    digest = tokens[4]

    argon2_hash = Argon2Hash(argon_variant, version, salt, digest)

    return argon2_hash


def verify(argon2_hash: str, password: str) -> bool:
    ph = argon2.PasswordHasher()

    try:
        ph.verify(argon2_hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
