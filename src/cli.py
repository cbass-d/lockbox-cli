from pathlib import Path
from rich.text import Text
from datetime import datetime, date
from os import mkdir
from enum import Enum
from platformdirs import user_data_dir

from keyring_database import KeyringDB, HashEntry
import ciphers
from console_config import console
import hashing

DB_PATH = ""

BANNER = Text('''
---------------------------------------------------------------------
 _     _____ _____  _   ________  _______   __  _____  _     _____
| |   |  _  /  __ \| | / /| ___ \|  _  \ \ / / /  __ \| |   |_   _|
| |   | | | | /  \/| |/ / | |_/ /| | | |\ V /  | /  \/| |     | |
| |   | | | | |    |    \ | ___ \| | | |/   \  | |    | |     | |
| |___\ \_/ / \__/\| |\  \| |_/ /\ \_/ / /^\ \ | \__/\| |_____| |_
\_____/\___/ \____/\_| \_/\____/  \___/\/   \/  \____/\_____/\___/

---------------------------------------------------------------------
''', style="banner")


class State(Enum):  # State of application
    START = 0
    ENCRYPT = 1
    DECRYPT = 2
    MANAGE = 3


def fetch_file_info(path: Path) -> list:
    owner = path.owner()
    size = str(path.stat().st_size)
    ltm = date.fromtimestamp(path.stat().st_mtime)
    ltm_str = ltm.strftime("%d/%m/%y %H:%M:%S")

    return list([owner, str(size), ltm_str])


def user_input(prompt: Text, password: bool) -> str:
    try:
        if password:
            input = console.input(prompt, password=True)
        else:
            input = console.input(prompt)
        if ((input.casefold() == "q") or (input.casefold() == "exit")):
            exit()
    except EOFError or KeyError:
        exit()

    return input


def invalid_warning(error: Text, clear: bool):
    error = error.append("Press Enter to retry. Ctr-D to exit.")
    console.print(error, justify="left", style="error")
    input_prompt = Text("")
    user_input(prompt=input_prompt, password=False)

    if clear:
        console.clear()
        console.print(BANNER)

    return


def reset() -> State:
    console.print("Press Enter to return to main menu. Ctr-D to exit.",
                  justify="left", style="header")
    user_input(Text(""), False)

    return State.START


def get_hash(keyring_db: KeyringDB) -> str:
    console.print("1 - Enter hash manually\n2 - Use hash from database\n3 - Return",
                  justify="left", style="default")
    prompt = Text(": ", style="prompt")

    while True:
        input = user_input(prompt, False)
        try:
            user_int = int(input)
            if user_int not in range(1, 4):
                invalid_warning(Text("(-) Invalid option."), False)
                continue
            else:
                break
        except ValueError:
            invalid_warning(Text("(-) Invalid input."), False)
            continue

    if user_int == 1:
        return manual_hash_entry()
    elif user_int == 2:
        return use_hash_from_db(keyring_db)


def create_argon2_hash() -> str:
    prompt = Text("\nEnter passphrase to use: ", style="prompt")
    passphrase = user_input(prompt=prompt, password=True)

    argon2_hash = hashing.hash_passphrase(passphrase)

    return argon2_hash


def create_new_hash_entry() -> list:
    new_hash = create_argon2_hash()

    prompt = Text("Add comments to key entry: ", style="header")
    comments = user_input(prompt=prompt, password=False)
    date_created = datetime.now()
    date_str = date_created.strftime("%m-%d-%y %H:%M:%S")

    return [date_str, comments, new_hash]


def manual_hash_entry() -> str:
    prompt = (Text("Enter hash: ", style="prompt"))
    while True:
        key = user_input(prompt, False)
        if not key.isascii():
            invalid_warning(
                Text("(-) Hash must only contain valid ASCII values\n"), clear=False)
            continue
        elif len(key) != 16:
            invalid_warning(
                Text("(-) Hash must be 32 characters long\n"), clear=False)
            continue
        else:
            break

    return hash


def use_hash_from_db(keyring_db: KeyringDB) -> str:
    # Fetch key ids in database
    valid_ids = keyring_db.get_valid_ids()

    if not valid_ids:
        invalid_warning(Text("(-) No stored hashes\n"), clear=True)
        return ""
    else:
        keyring_db.dump_keys()
        prompt = Text("Enter ID of hash to use: ", style="prompt")
        while True:
            input = user_input(prompt, password=False)
            try:
                hash_id = int(input)
                if hash_id not in valid_ids:
                    invalid_warning(
                        Text("(-) Hash ID does not exist\n"), clear=False)
                    continue
                else:
                    break
            except ValueError:
                invalid_warning(Text("(-) Invalid hash ID\n"), clear=False)
                continue

        # Verify use of key through correct passphrase
        prompt = Text("Entr passphrase for chosen hash: ", style="prompt")
        while True:
            input = user_input(prompt, password=False)
            if (keyring_db.verify_hash(input, hash_id)):
                hash = keyring_db.fetch_hash(hash_id)
                argon2_hash = hashing.parse_argon2_hash(hash)
                break
            else:
                invalid_warning(
                    Text("(-) Invalid passphrase provided for hash\n"), clear=False)

    return argon2_hash.digest


def delete_hash(keyring_db: KeyringDB) -> int:
    valid_ids = keyring_db.get_valid_ids()
    if not valid_ids:
        console.print("(-) No stored keys", justify="left", style="error")
        return -1

    keyring_db.dump_keys()
    while True:
        prompt = Text("ID of key to delete: ", style="prompt")
        input = user_input(prompt, password=False)

        try:
            key_id = int(input)
            if key_id not in valid_ids:
                invalid_warning(
                    Text("(-) Key ID does not exist\n"), clear=False)
                continue
            else:
                break
        except ValueError:
            invalid_warning(Text("(-) Invalid key id\n"), clear=False)
            continue

    return keyring_db.delete_hash(key_id)


def edit_comments(keyring_db: KeyringDB) -> int:
    valid_ids = keyring_db.get_valid_ids()

    if not valid_ids:
        invalid_warning(Text("(-) No keys stored\n"), clear=True)
        return -1

    keyring_db.dump_keys()
    while True:
        prompt = Text("Enter ID of entry to be edited: ", style="prompt")
        input = user_input(prompt, password=False)

        try:
            hash_id = int(input)
            if hash_id not in valid_ids:
                invalid_warning(
                    Text("(-) Hash ID does not exist\n"), clear=False)
                continue
            else:
                break
        except ValueError:
            invalid_warning(Text("(-) Invalid hash id\n"), clear=False)
            continue

    prompt = Text("Updated comments: ", style="prompt")
    updated_comment = user_input(prompt, password=False)
    update = [updated_comment, hash_id]

    return keyring_db.edit_comments(update)


def start_menu() -> State:
    while True:
        console.print("1 - Encrypt File\n2 - Decrypt File\n3 - Manage Stored Hashes",
                      justify="left", style="default")
        input = user_input(prompt=Text(": ", style="prompt"), password=False)
        try:
            user_int = int(input)
            if user_int not in range(1, 4):
                invalid_warning(Text("(-) Invalid option\n"), clear=True)
            else:
                state = user_int
                match state:
                    case 1:
                        state = State.ENCRYPT
                    case 2:
                        state = State.DECRYPT
                    case 3:
                        state = State.MANAGE
            break
        except ValueError:
            invalid_warning(Text("(-) Invalid input\n"), clear=True)
            continue

    return state


def chose_encryption(keyring_db: KeyringDB) -> State:
    while True:
        prompt = Text("Enter path to file: ", style="prompt")
        path_str = user_input(prompt, False)
        console.print("")
        path = Path(path_str)

        if not path.exists():
            invalid_warning(Text("(-) Path does not exist\n"), clear=True)
            continue
        elif path.is_dir():
            invalid_warning(Text("(-) Path is a directory\n"), clear=True)
            continue
        else:
            break

    # Display file info
    file_info = fetch_file_info(path)
    file_name = Text("FILE: " + path.name)

    while True:
        console.print(file_name + '\n' + "-" * len(file_name),
                      justify="left", style="header")
        console.print("Owner: " + file_info[0] + "\nSize: " + file_info[1] +
                      "\nLast modified: " + file_info[2] + '\n', justify="left", style="default")

        console.print("1 - Create and use new key\n2 - Use exisiting key\n3 - Return",
                      justify="left", style="default")
        input = user_input(prompt=Text(": ", style="prompt"), password=False)
        try:
            user_int = int(input)
            if user_int not in range(1, 4):
                invalid_warning(Text("(-) Invalid option\n"), clear=True)
        except ValueError:
            invalid_warning(Text("(-) Invalid input\n"), clear=True)
            continue

        if user_int == 1:
            hash_entry = create_new_hash_entry()
            hash_entry = HashEntry(
                date=hash_entry[0], comments=hash_entry[1], hash=hash_entry[2])
            keyring_db.store_hash(hash_entry)
            argon2_hash = hash_entry.hash

            # Parse argon2 string to structured object
            argon2_hash = hashing.parse_argon2_hash(argon2_hash)
            hash = argon2_hash.digest

        elif user_int == 2:
            hash = use_hash_from_db(keyring_db)
            if hash == "":
                console.print("(-) Unable to retrieve key",
                              justify="left", style="error")
                return State.ENCRYPT
        elif user_int == 3:
            return State.ENCRYPT

        break

    # Get name for output file
    prompt = Text("File to write output to: ", style="prompt")
    output_path = user_input(prompt, False)
    console.print("")
    output_path = Path(output_path)

    ciphers.encryption(path, hash, output_path)

    return reset()


def chose_decryption(keyring_db: KeyringDB) -> State:
    while True:
        prompt = Text("Enter path to encrypted file: ",
                      justify="left", style="prompt")
        path_str = user_input(prompt, False)
        console.print("")
        path = Path(path_str)
        if not path.exists():
            invalid_warning(Text("(-) Path does not exist\n"), clear=True)
            continue
        elif path.is_dir():
            invalid_warning(Text("(-) Path is a directory\n"), clear=True)
            continue
        else:
            break

    # Display file info
    file_info = list()
    file_info = fetch_file_info(path)
    file_name = Text("FILE: " + path.name)
    console.print(file_name + '\n' + "-" * len(file_name),
                  justify="left", style="header")
    console.print("Owner: " + file_info[0] + "\nSize: " + file_info[1] +
                  "\nLast modified: " + file_info[2] + '\n', justify="left", style="default")

    hash = get_hash(keyring_db)
    if hash == "":
        console.print("(-) Unable to get decryption key.",
                      justify="left", style="error")
        return State.DECRYPT

    # Get name for output file
    prompt = Text("File to write output to: ", style="prompt")
    output_path = user_input(prompt, False)
    console.print("")
    output_path = Path(output_path)

    ciphers.decryption(path, hash, output_path)

    return reset()


def chose_mgmt(keyring_db: KeyringDB) -> State:
    prompt = Text(": ", style="prompt")
    while True:
        console.print("1 - Dump Keys\n2 - Add New Hash\n3 - Delete Hash\n4 - Modify Comments\n5 - Return",
                      justify="left", style="default")
        input = user_input(prompt, False)
        try:
            user_int = int(input)
            if user_int not in range(1, 6):
                invalid_warning(Text("(-) Invalid option\n"), clear=True)
                continue
            else:
                break
        except ValueError:
            invalid_warning(Text("(-) Invalid input\n"), clear=True)

    match user_int:
        case 1:
            if not keyring_db.get_valid_ids():
                console.print("(-) No keys stored",
                              justify="left", style="error")
            else:
                keyring_db.dump_keys()
        case 2:
            hash_entry = create_new_hash_entry()
            hash_entry = HashEntry(
                date=hash_entry[0], comments=hash_entry[1], hash=hash_entry[2])
            keyring_db.store_hash(hash_entry)
            return State.MANAGE
        case 3:
            if delete_hash(keyring_db) == -1:
                invalid_warning(
                    Text("(-) Unable to delete hash\n"), clear=True)
                return State.MANAGE
        case 4:
            if edit_comments(keyring_db) == -1:
                invalid_warning(
                    Text("(-) Unable to update comments\n"), clear=True)
                return State.MANAGE
            else:
                console.print("(+) Successfully edited comment",
                              justify="left", style="header")
        case 5:
            return State.START

    return reset()


def main():
    # Get path for sqlite3 database
    data_dir = Path(user_data_dir("lockbox"))
    db_path = data_dir / "key-storage"
    keyring_db = KeyringDB(db_path)

    # Check if data directory and database already exists
    if not db_path.exists():
        print("[+] Creating data directory and key database")
        try:
            mkdir(data_dir)
        except FileNotFoundError as err:
            print("[-] Error creating data directory: ", err)
            raise
        except FileExistsError:
            print("[-] Data directory exists, but no key database found")
            print("[+] Creating new database")
        finally:
            keyring_db.initial_setup()

    # Main application loop
    state = State.START
    while True:
        console.clear()
        console.print(BANNER)
        match state:
            case State.START:
                state = start_menu()
                continue

            case State.ENCRYPT:
                state = chose_encryption(keyring_db)
                continue

            case State.DECRYPT:
                state = chose_decryption(keyring_db)
                continue

            case State.MANAGE:
                state = chose_mgmt(keyring_db)
                continue

            case _:
                break

    return


if __name__ == "__main__":
    main()
