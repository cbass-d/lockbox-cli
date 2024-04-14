import sqlite3
from rich.text import Text
from rich.table import Table
from pathlib import Path

from console_config import console


def handle_db_error(err: sqlite3.Error):
    console.print("Database error: " + str(err), justify="left", style="error")
    
    return

def check_for_db() -> int:

    if not (Path("keys.db").exists()):
        try:
            conn = sqlite3.connect("keys.db")
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
        conn = sqlite3.connect('file:keys.db?mode=ro', uri=True)
        res_cur = conn.execute("SELECT id FROM Keyring")
        res = res_cur.fetchall()
        valid_ids = list()
        for id in res:
            valid_ids.append(id[0])
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return list()
    
    conn.close
    return valid_ids

def dump_keys(display: bool) -> int:
    try:
        conn = sqlite3.connect('file:keys.db?mode=ro', uri=True)
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

    return count

# Manually add new key to keyring
def add_new_key(key_date: str,  key_comment: str, key: str) -> int:
    # prompt = Text("Enter key contents: ", style="prompt")

    # while True:
    #     user_key = get_input(prompt, False)
    #     if not user_key.isascii():
    #         invalid_warning(Text("(-) Key must only contain valid ASCII values."), False)
    #     elif len(user_key) != 16:
    #         invalid_warning(Text("(-) Key must be 16 characters long."), False)
    #     else: break
    
    # prompt = Text("Add comments to key: ", style="prompt")
    # key_comment = get_input(prompt, False)
    # key_date = datetime.now()
    # key_date_str = key_date.strftime("%m-%d-%y %H:%M:%S")

    try: 
        conn = sqlite3.connect('file:keys.db?mode=rw', uri=True)
        entry = [(None, key_date, key_comment, key)]
        conn.execute("""INSERT INTO Keyring VALUES(?,?,?,?)""", entry[0])
        conn.commit()
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1 

    conn.close()

    return 0

# Delete key entry from database
def delete_key(key_id: int) -> int:    
    
    try:
        conn = sqlite3.connect('file:keys.db?mode=rw', uri=True)
        conn.execute("DELETE FROM Keyring WHERE id = ?", (key_id,))
        conn.commit()
        console.print("(+) Deleted key #" + str(key_id), justify="left", style="header")

    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1          
    
    conn.close()

    return 0

def fetch_key(key_id: int) -> str:
    try:
        conn = sqlite3.connect('file:keys.db?mode=rw', uri=True)
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

    return key

# def store_key(key: str) -> int:
#     try:
#         conn = sqlite3.connect('file:keys.db?mode=rw', uri=True)

#         created_date = datetime.now()
#         created_str = created_date.strftime("%m-%d-%y %H:%M:%S")

#         prompt = Text("Add comments to key entry: ", style="prompt")
#         comments = get_input(prompt, False)
        
#         entry = [(None, created_str, comments, key)]
#         conn.execute("""INSERT INTO Keyring VALUES(?,?,?,?)""", entry[0])
#         conn.commit()
           
#     except sqlite3.Error as err:
#         if conn: conn.close()
#         handle_db_error(err)
#         return -1

#     conn.close()

#     return 0

# Edit comments in key entry
def change_comments(update: list) -> int:
    try:
        conn = sqlite3.connect('file:keys.db?mode=rw', uri=True)
        conn.execute("UPDATE Keyring SET comments = ? WHERE id = ?", update)
        conn.commit()
    except sqlite3.Error as err:
        if conn: conn.close()
        handle_db_error(err)
        return -1
    
    conn.close()

    return 0
     
