from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
import base64
from console_config import console


def encryption(file_path: str, digest: str, output: Path) -> int:

    # Open file
    try:
        file_path = Path(file_path)
        f = open(file_path, "rb")
    except Exception as err:
        console.print("(-) Unable to open file " +
                      file_path.as_posix() + ": " + str(type(err)), style="error")
        return -1
    finally:
        file_bytes = bytearray(f.read())
        f.close()

    # Argon2 digest is base64 encoded
    digest = base64.b64decode(digest + "==")
    aesgcm = AESGCM(digest)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)

    # Attach nonce to ciphertext for decrypting
    ciphertext_nonce = nonce + ciphertext

    with open(output, "wb") as of:
        of.write(ciphertext_nonce)

    console.print("(+) Encrypted data written to " +
                  output.as_posix(), style="header")


def decryption(file_path: str, digest: str, output: Path):

    # Open file
    try:
        file_path = Path(file_path)
        f = open(file_path, "rb")
    except Exception as err:
        console.print("(-) Unable to open file " +
                      file_path.as_posix() + ": " + str(type(err)), style="error")
        return -1
    finally:
        file_bytes = bytearray(f.read())
        f.close()

    digest = base64.b64decode(digest + "==")
    nonce = file_bytes[:12]
    ciphertext = file_bytes[12:]
    aesgcm = AESGCM(digest)
    try:
        cleartext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print("Unable to decrypt data with provided key")
        return

    with open(output, "wb") as of:
        of.write(cleartext)

    console.print("(+) Encrypted data written to " +
                  output.as_posix(), style="header")
