from sys import byteorder
from pathlib import Path
from bitarray import bitarray

import Encryption.boxes as boxes
from console_config import console

BYTE_ORDER = byteorder

############################### Encryption #########################################
def encrypt_data(data_bytes: bytearray, key_bytes: bytearray) -> bytearray:
    # 16 total rounds
    for round in range(1,17):
        round_key = get_round_key(key_bytes, round)

        # XOR the first byte of the round key with the block
        for byte in range(0,16):
            data_bytes[byte] ^= round_key[0]

        data_bytes = first_premutation(data_bytes)

        for iter in range(4):
            data_bytes[0:4] = f_one_enc(data_bytes[0:4], round_key)
            data_bytes[4:8] = f_two_enc(data_bytes[4:8])
            data_bytes[8:12] = f_three_enc(data_bytes[8:12], round_key)
            data_bytes[12:16] = f_four_enc(data_bytes[12:16])

            # Rotate the block 32-bits to the left
            data_bytes[:] = data_bytes[4:16] + data_bytes[0:4]

    return data_bytes

def first_premutation(data_bytes: bytearray) -> bytearray:
    res = bytearray(16)
    ind = 0
    for new_ind in boxes.FIRST_PHASE_P_BOX:
        res[ind] = data_bytes[new_ind - 1]
        ind += 1
    
    return res

def function_premutation(data_bytes: bytearray) -> bytearray:
    bits = bitarray()
    bits.frombytes(data_bytes)
    res = bitarray(32)
    ind = 0
    for new_ind in boxes.FUNCTION_PHASE_P_BOX:
        res[ind] = bits[new_ind - 1]
        ind += 1

    return bytearray(res.tobytes())


def f_one_enc(data_bytes: bytearray, round_key: bytearray):
    data_bytes[0] = int.from_bytes(boxes.S_BOX_ONE[data_bytes[0]], BYTE_ORDER)
    data_bytes[1] = int.from_bytes(boxes.S_BOX_TWO[data_bytes[1]], BYTE_ORDER)
    data_bytes[2] = int.from_bytes(boxes.S_BOX_THREE[data_bytes[2]], BYTE_ORDER)
    data_bytes[3] = int.from_bytes(boxes.S_BOX_FOUR[data_bytes[3]], BYTE_ORDER)

    # Rotate block - Get rotation amount by (1st 16-bits) * (2nd 16-bites) mod 32
    rot = (int.from_bytes(round_key[0:3], BYTE_ORDER) * int.from_bytes(round_key[3:5], BYTE_ORDER)) % 32
    block_int = int.from_bytes(data_bytes, BYTE_ORDER)
    res_int = (block_int >> rot)|(block_int << (32 - rot)) & 0xFFFFFFFF
    data_bytes[:] = int.to_bytes(res_int, 4, BYTE_ORDER)
    return data_bytes

def f_two_enc(data_bytes: bytearray) -> bytearray:
    return function_premutation(data_bytes)

def f_three_enc(data_bytes: bytearray, round_key: bytearray) -> bytearray:
    data_bytes[0] ^= round_key[0]
    data_bytes[1] ^= round_key[1]
    data_bytes[2] ^= round_key[2]
    data_bytes[3] ^= round_key[3]

    data_bytes[0] = int.from_bytes(boxes.S_BOX_ONE[data_bytes[0]], BYTE_ORDER)
    data_bytes[1] = int.from_bytes(boxes.S_BOX_TWO[data_bytes[1]], BYTE_ORDER)
    data_bytes[2] = int.from_bytes(boxes.S_BOX_THREE[data_bytes[2]], BYTE_ORDER)
    data_bytes[3] = int.from_bytes(boxes.S_BOX_FOUR[data_bytes[3]], BYTE_ORDER)
    
    return data_bytes

def f_four_enc(data_bytes: bytearray) -> bytearray:
    data_bytes[0] = int.from_bytes(boxes.S_BOX_ONE[data_bytes[0]], BYTE_ORDER)
    data_bytes[1] = int.from_bytes(boxes.S_BOX_TWO[data_bytes[1]], BYTE_ORDER)
    data_bytes[2] = int.from_bytes(boxes.S_BOX_THREE[data_bytes[2]], BYTE_ORDER)
    data_bytes[3] = int.from_bytes(boxes.S_BOX_FOUR[data_bytes[3]], BYTE_ORDER)

    return data_bytes
####################################################################################

############################### Decryption #########################################
def decrypt_data(data_bytes: bytearray, key_bytes: bytearray):
    # 16 total rounds
    for round in range(16, 0, -1):
        round_key = get_round_key(key_bytes, round)
        
        for function_iter in range(4):
            data_bytes[:] = data_bytes[-4:] + data_bytes[:-4]
            data_bytes[0:4] = f_one_dec(data_bytes[0:4], round_key)
            data_bytes[4:8] = f_two_dec(data_bytes[4:8])
            data_bytes[8:12] = f_three_dec(data_bytes[8:12], round_key)
            data_bytes[12:16] = f_four_dec(data_bytes[12:16])

        data_bytes = first_premutation_inv(data_bytes)

        for byte in range(0,16):
            data_bytes[byte] ^= round_key[0]

    return data_bytes

def first_premutation_inv(data_bytes: bytearray) -> bytearray:
    res = bytearray(16)
    for count, i in enumerate(boxes.FIRST_PHASE_P_BOX):
        res[i-1] = data_bytes[count]

    return res

def function_premutation_inv(data_bytes: bytearray) -> bytearray:
    bits = bitarray()
    bits.frombytes(data_bytes)
    res = bitarray(32)
    for count, i in enumerate(boxes.FUNCTION_PHASE_P_BOX):
        res[i-1] = bits[count]

    return bytearray(res.tobytes())

def f_one_dec(data_bytes: bytearray, round_key: bytearray) -> bytearray:
    # Undo rotation
    rot = (int.from_bytes(round_key[0:3], BYTE_ORDER) * int.from_bytes(round_key[3:5], BYTE_ORDER)) % 32
    block_int = int.from_bytes(data_bytes, BYTE_ORDER)
    res_int = ((block_int >> (32 - rot))|(block_int << rot)) & 0xFFFFFFFF
    data_bytes[:] = int.to_bytes(res_int, 4, BYTE_ORDER)

    # Inverse of S-box substitution
    data_bytes[0] = boxes.S_BOX_ONE.index(int.to_bytes(data_bytes[0], 1, BYTE_ORDER))
    data_bytes[1] = boxes.S_BOX_TWO.index(int.to_bytes(data_bytes[1], 1, BYTE_ORDER))
    data_bytes[2] = boxes.S_BOX_THREE.index(int.to_bytes(data_bytes[2], 1, BYTE_ORDER))
    data_bytes[3] = boxes.S_BOX_FOUR.index(int.to_bytes(data_bytes[3], 1, BYTE_ORDER))

    return data_bytes

def f_two_dec(data_bytes: bytearray) -> bytearray:
    return function_premutation_inv(data_bytes)

def f_three_dec(data_bytes: bytearray, round_key: bytearray) -> bytearray:
    data_bytes[0] = boxes.S_BOX_ONE.index(int.to_bytes(data_bytes[0], 1, BYTE_ORDER))
    data_bytes[1] = boxes.S_BOX_TWO.index(int.to_bytes(data_bytes[1], 1, BYTE_ORDER))
    data_bytes[2] = boxes.S_BOX_THREE.index(int.to_bytes(data_bytes[2], 1, BYTE_ORDER))
    data_bytes[3] = boxes.S_BOX_FOUR.index(int.to_bytes(data_bytes[3], 1, BYTE_ORDER))

    data_bytes[0] ^= round_key[0]
    data_bytes[1] ^= round_key[1]
    data_bytes[2] ^= round_key[2]
    data_bytes[3] ^= round_key[3]
   
    return data_bytes

def f_four_dec(data_bytes: bytearray) -> bytearray:
    data_bytes[0] = boxes.S_BOX_ONE.index(int.to_bytes(data_bytes[0], 1, BYTE_ORDER))
    data_bytes[1] = boxes.S_BOX_TWO.index(int.to_bytes(data_bytes[1], 1, BYTE_ORDER))
    data_bytes[2] = boxes.S_BOX_THREE.index(int.to_bytes(data_bytes[2], 1, BYTE_ORDER))
    data_bytes[3] = boxes.S_BOX_FOUR.index(int.to_bytes(data_bytes[3], 1, BYTE_ORDER))
    
    return data_bytes 
####################################################################################


def get_round_key(key_bytes: bytearray, round: int) -> bytearray:
    first_byte_pool = bytearray([0x08, 0x6A, 0xFA, 0x0F,0xD3, 0xA2, 0xB7, 0xE9,
                            0x14, 0x7A, 0x4B, 0x2C,0x5D, 0x7A, 0xF4, 0x1D])
    
    # Chose round based key part to premutate
    key_part = bytearray()
    if round in [1,5,9,13]: key_part = key_bytes[0:4]
    elif round in [2,6,10,14]: key_part = key_bytes[4:8]
    elif round in [3,7,11,15]: key_part = key_bytes[8:12]
    elif round in [4,8,12,16]: key_part = key_bytes[12:16]

    # Premutate key part
    temp_key = bytearray(4)
    if round in range(1,5):
        temp_key[0] = key_part[0] 
        temp_key[1] = key_part[1]
        temp_key[2] = key_part[2]
        temp_key[3] = key_part[3]
    elif round in range(5,9):
        temp_key[0] = key_part[1] 
        temp_key[1] = key_part[2]
        temp_key[2] = key_part[3]
        temp_key[3] = key_part[0]
    elif round in range(9, 13):
        temp_key[0] = key_part[2] 
        temp_key[1] = key_part[3]
        temp_key[2] = key_part[0]
        temp_key[3] = key_part[1]
    elif round in range(13,17):
        temp_key[0] = key_part[3] 
        temp_key[1] = key_part[0]
        temp_key[2] = key_part[1]
        temp_key[3] = key_part[2]
    
    # Make subkey
    subkey = bytearray(4)
    subkey[0] = first_byte_pool[round - 1]
    subkey[1:4] = temp_key

    return subkey

def run(file_path: Path, mode: int, key_str: str) -> int:
    # Open file
    try:
        file_path = Path(file_path)
        f = file_path.open("rb")
    except Exception as err:
        console.print("(-) Unable to open file " + file_path.as_posix() + ": " + str(type(err)), justify= "left", style="error")
        return -1
    
    file_bytes = bytearray(f.read())
    key_bytes = bytearray(key_str.encode('utf-8'))

    # Encryption
    if mode == 1:

        # Add neccessary padding to bytes
        pad = 16 - (len(file_bytes) % 16)
        for i in range(1, pad + 1):
            file_bytes.append(i)
        
        # Use 128-bit blocks
        total_blocks = len(file_bytes) // 16
        for n in range(0, (total_blocks) * 16, 16):
            file_bytes[n:n + 16] = encrypt_data(file_bytes[n:n + 16], key_bytes)

        # Write the encrypted file
        new_filename = file_path.as_posix() + ".enc"
        try:
            out_file = Path(new_filename).open("wb")
            out_file.write(file_bytes)
        except Exception as err:
            console.print("(-) Unable to write data at " + new_filename + ": " + str(type(err)), justify= "left", style="error")
            return -1
        console.print("(+) Encrypted data written to " + new_filename, justify="left", style="header")

    # Decryption
    elif mode == 2:

        # Use 128-bit blocks
        total_blocks = len(file_bytes) // 16
        for n in range(0, (total_blocks) * 16, 16):
            file_bytes[n:n + 16] = decrypt_data(file_bytes[n:n + 16], key_bytes)
        
        # TO-DO: Verify if properly decrypted

        # Remove padding
        pad = file_bytes[len(file_bytes) - 1]
        for i in range(pad):
            file_bytes.pop()

        # Write the decrypted file
        try:
            new_filename = file_path.as_posix().replace(".enc", "")
            out_file = Path(new_filename).open("wb")
            out_file.write(file_bytes)
        except:
            console.print("(-) Unable to write data at " + new_filename + ": " + str(type(err)), justify= "left", style="error")
            return -1
        console.print("(+) Decrypted data written to " + new_filename, justify="left", style="header")

    return 0