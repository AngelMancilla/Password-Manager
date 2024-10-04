import json, hashlib, getpass, os, pyperclip, sys, time
from cryptography.fernet import Fernet

# Function for Hashing the Master Password
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

# Generate a secret key
def generate_key():
    return Fernet.generate_key()

# Initialize Fernet cipher with provided key
def initialize_cipher(key):
    return Fernet(key)

# Function to encrypt a password
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

# Function to decrypt a password
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# Function to save data to JSON file
def save_json(file_name, data):
    with open(file_name, 'w') as file:
        json.dump(data, file, indent=4)

# Function to load data from JSON file safely
def load_json(file_name):
    if not os.path.exists(file_name):
        return []
    with open(file_name, 'r') as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return []

# Function to register user
def register(username, master_password):
    # Encrypt master password before storing it 
    hashed_master_password = hash_password(master_password)
    user_data = {"username": username, "master_password": hashed_master_password}
    
    save_json("user_data.json", user_data)
    print("\n[+] Registration complete.\n")

# Function to log you in 
def login(username, entered_password):
    try:
        with open("user_data.json", "r") as file:
            user_data = json.load(file)
    except FileNotFoundError:
        print("\n[-] No user found. Please register first.\n")
        return False

    stored_password_hash = user_data.get("master_password")
    entered_password_hash = hash_password(entered_password)
    
    if entered_password_hash == stored_password_hash and username == user_data.get("username"):
        print("\n[+] Login Successful..\n")
        return True
    else:
        print("\n[-] Invalid Login credentials.\n")
        return False

# Function to view saved websites
def view_websites():
    try:
        data = load_json("passwords.json")
        if not data:
            print("\n[-] No websites found.\n")
            return
        print("\nWebsites you saved...\n")
        for x in data:
            print(x["website"])
        print("\n")
    except FileNotFoundError:
        print("\n[-] No saved passwords.\n")

# Function to add (save) password.
def add_password(website, password):
    data = load_json('passwords.json')
    encrypted_password = encrypt_password(cipher, password)
    password_entry = {'website': website, 'password': encrypted_password}
    data.append(password_entry)
    save_json('passwords.json', data)
    print("\n[+] Password added!\n")

# Function to retrieve a saved password
def get_password(website):
    data = load_json('passwords.json')
    for entry in data:
        if entry['website'] == website:
            decrypted_password = decrypt_password(cipher, entry['password'])
            pyperclip.copy(decrypted_password)
            print(f"\n[+] Password for {website}: {decrypted_password}")
            print("[+] Password copied to clipboard.")
            clear_clipboard()  # Clear clipboard after a delay
            return decrypted_password
    print("\n[-] Password not found! Did you save the password?\n")
    return None

# Function to clear clipboard after a delay for security
def clear_clipboard(delay=10):
    time.sleep(delay)
    pyperclip.copy("")
    print("[+] Clipboard cleared.")

# Load or generate the encryption key
key_filename = "encryption_key.key"
if os.path.exists(key_filename):
    with open(key_filename, "rb") as key_file:
        key = key_file.read()
else:
    key = generate_key()
    with open(key_filename, "wb") as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)

def show_welcome():
    print("********************************************")
    print("*                                          *")
    print("*      WELCOME TO YOUR PASSWORD MANAGER    *")
    print("*                                          *")
    print("********************************************\n")

show_welcome()

# Infinite loop to keep the program running until the user chooses to quit.
while True:
    print("1. Register")
    print("2. Login")
    print("3. Quit")
    choice = input("Enter your choice: ")
    
    if choice == '1':  # Registration
        file = 'user_data.json'
        if os.path.exists(file) and os.path.getsize(file) != 0:
            print("\n[-] Master user already exists!")
        else:
            username = input("Enter your username: ")
            master_password = getpass.getpass("Enter your master password: ")
            register(username, master_password)

    elif choice == '2':  # Login
        file = 'user_data.json'
        if os.path.exists(file):
            username = input("Enter your username: ")
            master_password = getpass.getpass("Enter your master password: ")
            if login(username, master_password):
                # After successful login
                while True:
                    print("1. Add Password")
                    print("2. Get Password")
                    print("3. View Saved Websites")
                    print("4. Quit")
                    password_choice = input("Enter your choice: ")
                    
                    if password_choice == '1':  # Add a password
                        website = input("Enter website: ")
                        password = getpass.getpass("Enter password: ")
                        add_password(website, password)

                    elif password_choice == '2':  # Get a password
                        website = input("Enter website: ")
                        get_password(website)

                    elif password_choice == '3':  # View saved websites
                        view_websites()

                    elif password_choice == '4':  # Quit inner menu
                        break

        else:
            print("\n[-] You have not registered. Please do that.\n")

    elif choice == '3':  # Quit the main program
        break

   
