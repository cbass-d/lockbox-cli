import argon2
from pathlib import Path
from rich.text import Text
from filetype import guess
from datetime import datetime, date
from os import remove

import Encryption.nsses as nsses
import db_operations as db
from console_config import console

BANNER = Text('''
  _   _   ____    ____    _____   ____  
 | \ | | / ___|  / ___|  | ____| / ___| 
 |  \| | \___ \  \___ \  |  _|   \___ \ 
 | |\  |  ___) |  ___) | | |___   ___) |
 |_| \_| |____/  |____/  |_____| |____/ 
    Not So Simple Encryption Scheme
''', style="banner")

def fetch_file_info(path: Path) -> list:
    type = guess(path)
    if type is None:
        type = '-'
        console.print("(-) Unable to guess file type.", justify="left", style="error")
    
    owner = path.owner()
    size = str(path.stat().st_size)
    ltm = date.fromtimestamp(path.stat().st_mtime)
    ltm_str = ltm.strftime("%d/%m/%y %H:%M:%S")

    return list([type, owner, str(size), ltm_str])

def get_input(prompt: Text, password: bool) -> str:
    try:
        if password: input = console.input(prompt, password=True)
        else: input = console.input(prompt)
        if ((input.casefold() == "q") or (input.casefold() == "exit")): 
            exit()
    except EOFError or KeyError:
        exit()
    
    return input

def invalid_warning(error: Text, clear: bool):
    error = error.append("Press Enter to retry. Ctr-D to exit.")
    console.print(error, justify="left", style="error")
    input_prompt = Text("")
    get_input(input_prompt, False)
    
    if clear: 
        console.clear()
        console.print(BANNER)
    
    return

def reset() -> int:
    console.print("Press Enter to return to main menu. Ctr-D to exit.", justify="left", style="header")
    get_input(Text(""), False)
    
    return start

def get_dec_key() -> str:
    console.print("1 - Enter key manually\n2 - Use key from database\n3 - Return", justify="left", style="default")
    prompt = Text(": ", style="prompt")
    
    while True:
        user_input = get_input(prompt, False)
        try:
            user_int = int(user_input)
            if user_int not in range(1,4):
                invalid_warning(Text("(-) Invalid option."), False)
                continue
            else: break
        except ValueError:
            invalid_warning(Text("(-) Invalid input."), False)
            continue
    
    if user_int == 1:
        return enter_key_manualy()
    elif user_int == 2:
        return use_key_from_db()
    
    return ""

def create_key_from_passphrase(store_prompt: bool) -> list:
    prompt = Text("\nEnter passphrase to use: ", style="prompt")
    passphrase = get_input(prompt, True)
    argon_hasher = argon2.PasswordHasher()
    ph = argon_hasher.hash(passphrase)
    enc_key = ph[-16:]

    prompt = Text("Add comments to key entry: ", style="prompt")
    comments = get_input(prompt, False)

    created_date = datetime.now()
    created_str = created_date.strftime("%m-%d-%y %H:%M:%S")
    
    if store_prompt:
        prompt = Text("Store key in database? [Y/N] ")
        store = get_input(prompt, False)
        store = store.casefold()
        if store == "y" or store == "yes":
            console.print("(+) Storing key.", justify="left", style="header")
            db.add_new_key(created_str, comments, enc_key)
    else:
        db.add_new_key(created_str, comments, enc_key)
 
    return [created_str, comments, enc_key]


def enter_key_manualy() -> str:
    prompt = (Text("Enter key contents: ", style="prompt"))
    while True:
        key = get_input(prompt, False)
        if not key.isascii():
            invalid_warning(Text("(-) Key must only contain valid ASCII values."), False)
            continue
        elif len(key) != 16:
            invalid_warning(Text("(-) Key must be 16 characters long."), False)
            continue
        else: 
            break
    
    return key

def use_key_from_db() -> str:
    # Fetch keys in database
    valid_ids = db.get_valid_ids()
    
    if not valid_ids:
        invalid_warning(Text("(-) No stored keys.\n"), True)
        return ""
    else:
        db.dump_keys(True)
        prompt = Text("Enter ID of key to use: ", style="prompt")
        while True:
            user_input = get_input(prompt, False)
            try:
                chosen_id = int(user_input)
                if chosen_id not in valid_ids:
                    invalid_warning(Text("(-) Key ID does not exist."), False)
                    continue
                else: break
            except ValueError:
                invalid_warning(Text("(-) Invalid key ID."), False)
                continue
        # Fetch chosen key from db
        key = db.fetch_key(chosen_id)                        
    
    return key

def choose_key_to_delete() -> int:
    valid_ids = db.get_valid_ids()
    if not valid_ids:
        console.print("(-) No stored keys", justify="left", style="error")
        return -1
    
    else:
        db.dump_keys(True)
        while True:
            prompt = Text("ID of key to remove: ", style="prompt")
            key_id_str = get_input(prompt, False)

            try:
                key_id = int(key_id_str)
                if key_id not in valid_ids:
                    invalid_warning(Text("(-) Key ID does not exist."), False)
                    continue
                else: break
            except ValueError:
                invalid_warning(Text("(-) Invalid key id."), False)
                continue
    
        return db.delete_key(key_id)
    
def edit_comments() -> int:
    valid_ids = db.get_valid_ids()

    if not valid_ids:
        invalid_warning(Text("(-) No keys stored."), True)
        return -1
    else:
        db.dump_keys(True)
        while True:
            prompt = Text("Enter ID of entry to be edited: ", style="prompt")
            key_id_str = get_input(prompt, False)

            try:
                key_id = int(key_id_str)
                if key_id not in valid_ids:
                    invalid_warning(Text("(-) Key ID does not exist."), False)
                    continue
                else: break
            except ValueError:
                invalid_warning(Text("(-) Invalid key id"), False)
                continue
    
        prompt = Text("Change comment: ", style="prompt")
        user_comment = get_input(prompt, False)
        update = [user_comment, key_id]

        return db.change_comments(update)


def start_menu() -> int:
    while True:
        console.print("1 - Encrypt File\n2 - Decrypt File\n3 - Manage Stored Keys", justify="left", style="default")
        user_input = get_input(Text(": ", style="prompt"), False)
        try:
            user_int = int(user_input)
            if user_int not in range(1,4): invalid_warning(Text("(-) Invalid option."), True)
            else: 
                state = user_int
                break
        except ValueError:
            invalid_warning(Text("(-) Invalid input."), True)
            continue
    
    return state

def chose_encryption() -> int:
    while True:
        prompt = Text("Enter path to file: ", style="prompt")
        path_str = get_input(prompt, False)
        console.print("")
        path = Path(path_str)

        if not path.exists():
            invalid_warning(Text("(-) Path does not exist."), True)
            continue
        elif path.is_dir():
            invalid_warning(Text("(-) Path is a directory."), True)
            continue
        else: break

    # Display file info
    info = fetch_file_info(path)
    file_name = Text("FILE: " + path.name)
    
    while True:
        console.print(file_name + '\n' + "-" * len(file_name), justify="left", style="header")
        console.print("Type: " + info[0] + "\nOwner: " + info[1] + "\nSize: " + info[2] + "\nLast modified: " + info[3] + '\n', justify="left", style="default")
        
        console.print("1 - Create and use new key\n2 - Use exisiting key\n3 - Return", justify="left", style="default")
        user_input = get_input(Text(": ", style="prompt"), False)
        try:
            user_int = int(user_input)
            if user_int not in range(1,4): invalid_warning(Text("(-) Invalid option."), True)
        except ValueError:
            invalid_warning(Text("(-) Invalid input."), True)
            continue

        if user_int == 1:
            enc_key = create_key_from_passphrase(store_prompt=True)[2]            
        elif user_int == 2:
            enc_key = use_key_from_db()
        
        if enc_key == "":
            console.print("(-) Unable to retrieve key.", justify="left", style="error")
            return encrypt
        elif user_int == 3:
            return encrypt

        break

    nsses.run(path, 1, enc_key)

    try:
        remove(path)
    except:
        console.print("(-) Error deleting file: " + path.as_posix(), style="error")
        invalid_warning("", True)
        return encrypt
    
    return reset()

def chose_decryption() -> int:
    while True:
        prompt = Text("Enter path to encrypted file: ", justify="left", style="prompt")
        path_str = get_input(prompt, False)
        console.print("")
        path = Path(path_str)
        if not path.exists():
            invalid_warning(Text("(-) Path does not exist."), True)
            continue
        elif path.is_dir():
            invalid_warning(Text("(-) Path is a directory."), True)
            continue
        else: break
    
    # Display file info
    info = list()
    info = fetch_file_info(path)
    file_name = Text("FILE: " + path.name)
    console.print(file_name + '\n' + "-" * len(file_name), justify="left", style="header")
    console.print("Owner: " + info[1] + "\nSize: " + info[2] + "\nLast modified: " + info[3] + '\n', justify="left", style="default")

    key = get_dec_key()
    if key == "":
        console.print("(-) Unable to get decryption key.", justify="left", style="error")
        return decrypt
    else:
        nsses.run(path, 2, key)

        try:
            remove(path)
        except:
            console.print("(-) Error deleting file: " + path.as_posix(), style="error")
            invalid_warning("", True)
            return decrypt
    
    return reset()

def chose_mgmt() -> int:
    prompt = Text(": ", style="prompt")
    while True:
        console.print("1 - Dump Keys\n2 - Add Key\n3 - Delete Key\n4 - Modify Comments\n5 - Return", justify="left", style="default")
        user_input = get_input(prompt, False)
        try:
            user_int = int(user_input)
            if user_int not in range(1, 6):
                invalid_warning(Text("(-) Invalid option."), True)
                continue
            else: break
        except:
            invalid_warning(Text("(-) Invalid option."), True)
    
    if user_int == 1:
        if db.dump_keys(True) == 0:
            console.print("(-) No keys stored.", justify="left", style="error")
    elif user_int == 2:
        if create_key_from_passphrase(store_prompt=False) == None:
            return manage
    elif user_int == 3:
        if choose_key_to_delete() == -1:
            invalid_warning(Text("(-) Unable to delete key."), True)
            return manage
    elif user_int == 4:
        if edit_comments() == -1:
            return manage
        else: console.print("(+) Successfully edited comment", justify="left", style="header")
    elif user_int == 5:
        return start

    return reset()

def initial_setup():
    # prompt = Text("Enter passphrase to use to encrypt Keyring database: ", style="prompt")
    # passphrase = get_input(prompt, True)
    # argon_hasher = argon2.PasswordHasher()
    # argon_hasher.hash_len = 16
    # ph = argon_hasher.hash(passphrase)
    # enc_key = ph[-16:]

    return

def open_db():
    return

def main():
    global start, encrypt, decrypt, manage
    start = 0
    encrypt = 1
    decrypt = 2
    manage = 3
    
    state = start
    
    ## TO-DO: Add encryption for Keyring Database
    db_exists = db.check_for_db()
    if db_exists== -1:
        exit()
    elif db_exists == 1:
        initial_setup()
    else:
        open_db()

    while True:
        console.clear()
        console.print(BANNER)
        match state:
            case 0: # START
                state = start_menu()
                continue

            case 1: # ENC
                state = chose_encryption()
                continue

            case 2: # DEC
                state = chose_decryption()
                continue

            case 3: # MGMT
                state = chose_mgmt()
                continue
            
            case _:
                break

if __name__ == "__main__":
    main()