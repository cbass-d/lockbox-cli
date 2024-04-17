from Crypto.Cipher import AES
from Crypto.Util import Padding
from pathlib import Path

from console_config import console

def encryption(file_path: str, enc_key: bytearray):

    #Open file
    try:
        file_path = Path(file_path)
        f = open(file_path, "rb")
    except Exception as err:
        console.print("(-) Unable to open file " + file_path.as_posix() + ": " + str(type(err)), style="error")
        return -1
    
    file_bytes = bytearray(f.read())

    file_bytes = Padding.pad(file_bytes, 16)
    key = enc_key[:16]
    iv = enc_key[-16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    file_bytes = cipher.encrypt(file_bytes)

    new_path = Path(file_path.as_posix() + ".enc")
    of = open(new_path, "wb")
    of.write(file_bytes)

    console.print("(+) New encrypted data written to " + new_path.as_posix(), style="header")


def decryption(file_path: str, enc_key: str):

    #Open file
    try:
        file_path = Path(file_path)
        f = open(file_path, "rb")
    except Exception as err:
        console.print("(-) Unable to open file " + file_path.as_posix() + ": " + str(type(err)), style="error")
        return -1
    
    file_bytes = bytearray(f.read())
    key = enc_key[:16]
    iv = enc_key[-16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    file_bytes = cipher.decrypt(file_bytes)
    file_bytes = Padding.unpad(file_bytes, 16)


    new_path = Path(file_path.as_posix().removesuffix(".enc"))
    of = open(new_path, "wb")
    of.write(file_bytes)

    console.print("(+) New decrypted data written to " + new_path.as_posix(), style="header")


def encryption_db(file_path: str, enc_key: bytes):
    #Open file
    try:
        file_path = Path(file_path)
        f = open(file_path, "rb")
    except Exception as err:
        console.print("(-) Unable to open file " + file_path.as_posix() + ": " + str(type(err)), style="error")
        return -1
    
    file_bytes = bytearray(f.read())
    key = enc_key

    cipher  = AES.new(key, AES.MODE_ECB)
    file_bytes = cipher.encrypt(file_bytes)

    new_path = Path(file_path.as_posix() + ".enc")
    of = open(new_path, "wb")
    of.write(file_bytes)

    console.print("(+) New encrypted data written to " + new_path.as_posix(), style="header")

def decryption_db(file_path: str, enc_key: str):
    #Open file
    try:
        file_path = Path(file_path)
        f = open(file_path, "rb")
    except Exception as err:
        console.print("(-) Unable to open file " + file_path.as_posix() + ": " + str(type(err)), style="error")
        return -1
    
    file_bytes = bytearray(f.read())
    key = enc_key

    cipher  = AES.new(key, AES.MODE_ECB)
    file_bytes = cipher.decrypt(file_bytes)

    new_path = Path(file_path.as_posix().removesuffix(".enc"))
    of = open(new_path, "wb")
    of.write(file_bytes)

    console.print("(+) New decrypted data written to " + new_path.as_posix(), style="header")
