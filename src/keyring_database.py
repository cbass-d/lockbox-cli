import sqlite3
from dataclasses import dataclass
from rich.table import Table

from console_config import console
import hashing


@dataclass
class HashEntry:
    date: str
    comments: str
    hash: str


class KeyringDB:
    def __init__(self, db_path: str):
        self.db_path = db_path

    # Initial setup of key ring database
    def initial_setup(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE Keyring(id integer primary key autoincrement, created text, comments text, hash text)")
        except sqlite3.Error as err:
            print("sqlite3 error: ", err)
            raise
        finally:
            if conn:
                conn.close()
        return

    def get_valid_ids(self) -> list:
        try:
            conn = sqlite3.connect(
                'file:' + str(self.db_path) + '?mode=ro', uri=True)
            cursor = conn.execute("SELECT id FROM Keyring")
            res = cursor.fetchall()
            valid_ids = list()

            for id in res:
                valid_ids.append(id[0])
        except sqlite3.Error as err:
            print("Error getting key IDs from database: ", err)
        finally:
            if conn:
                conn.close()

        return valid_ids

    def store_hash(self, hash_entry: HashEntry) -> int:
        try:
            conn = sqlite3.connect(self.db_path)
            new_entry = [
                (None, hash_entry.date, hash_entry.comments, hash_entry.hash)]
            conn.execute(
                "INSERT INTO keyring VALUES(?, ?, ?, ?)", new_entry[0])
            conn.commit()
        except sqlite3.Error as err:
            print("Error inserting new hash: ", err)
            return -1
        finally:
            if conn:
                conn.close()

        return 0

    def dump_keys(self) -> int:
        try:
            conn = sqlite3.connect(
                'file:' + str(self.db_path) + '?mode=ro', uri=True)
            cursor = conn.execute("SELECT * FROM keyring")
            hashes = cursor.fetchall()
        except sqlite3.Error as err:
            print("Error getting hashes from database: ", err)
            return -1
        finally:
            if conn:
                conn.close()

        table = Table()
        table.add_column("ID", justify="left", style="header")
        table.add_column("Created", justify="left", style="header")
        table.add_column("Comments", justify="left", style="header")
        table.add_column("Hash", justify="left", style="header")

        if hashes:
            for entry in hashes:
                id, created, comments, hash = entry
                table.add_row(str(id), created, comments, hash)
            console.print("Hashes in Keyring\n" + "-" * 15,
                          justify="left", style="header")
            console.print(table)

        return 0

    def verify_hash(self, input: str, hash_id: id) -> bool:
        try:
            conn = sqlite3.connect(
                'file:' + str(self.db_path) + '?mode=ro', uri=True)
            cursor = conn.execute(
                "SELECT hash from keyring WHERE id = ?", (hash_id,))
            argon2_hash = cursor.fetchone()[0]
        except sqlite3.Error as err:
            print("Error fetching hash from database: ", err)
            return False
        finally:
            if conn:
                conn.close()

        return hashing.verify(argon2_hash, input)

    def fetch_hash(self, id: int) -> str:
        try:
            conn = sqlite3.connect(
                'file:' + str(self.db_path) + '?mode=ro', uri=True)
            cursor = conn.execute(
                "SELECT hash FROM keyring WHERE id = ?", (id,))
            res = cursor.fetchone()
        except sqlite3.Error as err:
            print("Error fetching hash from database: ", err)
            return ""
        finally:
            if conn:
                conn.close()

        if not res:
            return ""
        else:
            hash = res[0]

        return hash

    def delete_hash(self, id: int) -> int:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM keyring WHERE id = ?", (id,))
            conn.commit()
            console.print("(+) Deleted hash #" + str(id),
                          justify="left", style="header")
        except sqlite3.Error as err:
            print("Unable to delete key: ", err)
            return -1
        finally:
            if conn:
                conn.close()

        return 0

    def edit_comments(self, update: list) -> int:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "UPDATE keyring SET comments = ? WHERE id = ?", update)
            conn.commit()
        except sqlite3.Error as err:
            print("Unable to update comments: ", err)
            return -1
        finally:
            if conn:
                conn.close()

        return 0
