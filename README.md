# Password Manager in Python

This is a simple and secure Password Manager built using Python. It allows you to store, retrieve, and manage your passwords securely, using encryption for data protection. Passwords are stored in a local JSON file and encrypted using **Fernet** encryption.

## Features

- **Registration & Login**: Create a master account with a hashed master password.
- **Add Passwords**: Save encrypted passwords for various websites.
- **Retrieve Passwords**: Decrypt and copy passwords to the clipboard for easy use.
- **View Saved Websites**: Display a list of websites for which passwords have been stored.
- **Clipboard Security**: Automatically clears the clipboard after a few seconds to prevent leaks.

## Prerequisites

Before running the program, make sure you have the following installed:

1. **Python 3.x** installed on your machine.
2. Install the required Python libraries:
    - `cryptography` for encryption and decryption.
    - `pyperclip` for clipboard management.

You can install the necessary dependencies with the following command:

```bash
pip install cryptography pyperclip
