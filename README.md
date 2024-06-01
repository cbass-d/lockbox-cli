# LOCKBOX CLI
## CLI for encrypting files

LOCKBOX CLI is a Python program designed to provide encryption and decryption functionalities in a 
user-friendly console environment. Below is a brief overview of the program's features and functionalities:

### Setup
* The program utilizes a keyring database (keys.db) to store encryption keys securely.
* During the initial setup, users are prompted to enter a passphrase to encrypt the keyring database. This passphrase is not stored and is used solely for encryption purposes.

### Encryption and Decryption
* Users can encrypt and decrypt files using the AES encryption algorithm
* Encryption requires the use of a key, which can either be entered manually or retrieved from the keyring database.

### Management
* Users can manage encryption keys stored in the keyring database. This includes adding new keys, deleting existing keys, 
and modifying key comments.

### Running
A python virtual enviornment (venv) is used to run the CLI

To run LOCKBOX CLI:  
```
$ cd build  
$ make  
$ cd .. 
$ source virtual_env/bin/activate
$ mkdir db
$ python3 src/cli.py
```
To exit venv:
```
$ deactivate
