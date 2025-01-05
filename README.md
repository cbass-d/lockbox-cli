# LOCKBOX CLI
## CLI for encrypting files

LOCKBOX CLI is a Python program designed to provide encryption and decryption functionalities in a 
user-friendly console environment. Below is a brief overview of the program's features and functionalities:

### Setup
* The program utilizes a keyring database (lockbox/keys-storage inside user's data directory) to store password hashes used for encryption.

### Encryption and Decryption
* Users can encrypt and decrypt files using the AESGCM encryption algorithm
* Encryption requires the use of a hash, which can either be entered manually or retrieved from the keyring database.

### Management
* Users can manage encryption hashes stored in the keyring database. This includes adding new hashes, deleting existing hashes, 
and modifying hash comments.

### Running
A python virtual enviornment (venv) is used to run the CLI

To run LOCKBOX CLI:  
```
$ cd build  
$ make  
$ cd .. 
$ source virtual_env/bin/activate
$ python3 src/cli.py
```
To exit venv:
```
$ deactivate
