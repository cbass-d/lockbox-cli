import sqlite3
import argon2
from rich.table import Table
from pathlib import Path
from src.Encryption import nses
from os import remove, environ
from pathlib import Path

from console_config import console

DB_PATH = Path("./db/keys.db")

def handle_db_error(err: sqlite3.Error):
    console.print("Database error: " + str(err), justify="left", style="error")
    return

def check_for_db() -> int:
    if not (Path(str(DB_PATH)+".enc").exists()):
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("CREATE TABLE Keyring(id integer primary key autoincrement, created text, comments text, key text)")
            conn.close()
            return 1
        except sqlite3.Error as err:
            if conn: conn.close()
            handle_db_error(err)
            return -1
    
    return 0

def get_valid_ids() -> list:
    try:
        open_db()
        conn = sqlite3.connect('file:' + str(DB_PATH) + '?mode=ro', uri=True)
        res_cur = conn.execute("SELECT id FROM Keyring")
        res = res_cur.fetchall()
        valid_ids = list()
        
        for id in res:
            valid_ids.append(id[0])

    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return list()
    
    conn.close()
    close_db()
    return valid_ids

def dump_keys(display: bool) -> int:
    try:
        open_db()
        conn = sqlite3.connect('file:' + str(DB_PATH) + '?mode=ro', uri=True)
        res_cur = conn.execute("SELECT Count(*) FROM Keyring")
        count = res_cur.fetchone()[0]

        if not display:
            conn.close()
            return count
        
        res_cur = conn.execute("SELECT * FROM Keyring")
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1
    
    table = Table()
    table.add_column("ID", justify="left", style="header")
    table.add_column("Created", justify="left", style="header")
    table.add_column("Comments", justify="left", style="header")
    table.add_column("Key", justify="left", style="header")

    res = res_cur.fetchall()
    if res:
        for entry in res:
            entry_id, entry_date, entry_comm, entry_key = entry
            table.add_row(str(entry_id), entry_date, entry_comm, entry_key)
        console.print("Keys in Keyring\n" + "-" * 15, justify="left", style="header")
        console.print(table)  

    conn.close()
    close_db()
    return count

# Manually add new key to keyring
def add_new_key(key_date: str,  key_comment: str, key: str) -> int:
    try: 
        open_db()
        conn = sqlite3.connect('file:' + str(DB_PATH) + '?mode=rw', uri=True)
        entry = [(None, key_date, key_comment, key)]
        conn.execute("INSERT INTO Keyring VALUES(?,?,?,?)", entry[0])
        conn.commit()
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1 

    conn.close()
    close_db()
    return 0

# Delete key entry from database
def delete_key(key_id: int) -> int:    
    try:
        open_db()
        conn = sqlite3.connect('file:' + str(DB_PATH) + '?mode=rw', uri=True)
        conn.execute("DELETE FROM Keyring WHERE id = ?", (key_id,))
        conn.commit()
        console.print("(+) Deleted key #" + str(key_id), justify="left", style="header")
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1          
    
    conn.close()
    close_db()
    return 0

def fetch_key(key_id: int) -> str:
    try:
        open_db()
        conn = sqlite3.connect('file:'+str(DB_PATH)+'?mode=rw', uri=True)
        res_cur = conn.execute("SELECT key FROM Keyring WHERE id = ?", (key_id,))
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return ""
    
    res = res_cur.fetchone()
    if not res:
        return ""
    else:
        key = res[0]
    
    conn.close()
    close_db()
    return key

# Edit comments in key entry
def change_comments(update: list) -> int:
    try:
        open_db()
        conn = sqlite3.connect('file:' + str(DB_PATH) + '?mode=rw', uri=True)
        conn.execute("UPDATE Keyring SET comments = ? WHERE id = ?", update)
        conn.commit()
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1
    
    conn.close()
    close_db()
    return 0
     
# Verify the hash to use key
def verify_hash(phrase: str, key_id: int) -> bool:
    try:
        open_db()
        conn = sqlite3.connect('file:' + str(DB_PATH) + '?mode=ro', uri=True)
        res_cur = conn.execute("SELECT key FROM Keyring WHERE id = ?", (key_id,))
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return False

    try:
        valid = argon2.PasswordHasher().verify(res_cur.fetchone()[0], phrase)
        if conn: conn.close()
        close_db()
        return valid
    except argon2.exceptions.VerifyMismatchError or argon2.exceptions.VerificationError as err:
        if conn: conn.close()
        close_db()
        return False

# Check if decrypted DB maintained integrity
def db_okay(db_path: str) -> bool:
    try:
        conn = sqlite3.connect('file:' + db_path + '?mode=ro', uri=True)
        conn.execute("PRAGMA integrity_check")
    except sqlite3.Error as err:
        # if conn: conn.close()
        handle_db_error(err)
        return False

    conn.close()
    return True

def open_db():
    nses.run(str(DB_PATH)+".enc", 2, environ.get("MAIN_KEY"))
    remove(Path(str(DB_PATH)+".enc"))
    return

def close_db():
    nses.run(DB_PATH, 1, environ.get("MAIN_KEY"))
    remove(DB_PATH)
    return