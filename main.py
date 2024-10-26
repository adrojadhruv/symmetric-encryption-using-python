from cryptography.fernet import Fernet
from tkinter import *
from tkinter import filedialog, messagebox
import datetime

# Initialize window with dark theme
window = Tk()
window.title('File Encryptor and Decryptor')
window.geometry("800x500")
window.config(background="#1a1a1d")

# Functions
def browse_files():
    browse_files.filename = filedialog.askopenfilename(initialdir="/", title="Select a File")
    label_file_explorer.config(text=f"File Selected: {browse_files.filename}" if browse_files.filename else "No file selected")
    if browse_files.filename:
        show_controls()

def encrypt_file(p_word):
    temp_key = p_word.get().strip()
    if not temp_key:
        messagebox.showwarning("Warning", "Please enter a password for encryption.")
        return

    key = temp_key.ljust(43, "s")[:43] + "="
    fernet = Fernet(key)

    try:
        with open(browse_files.filename, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)

        with open(browse_files.filename, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

        status_label.config(text="File encrypted successfully", fg="#4caf50")
        save_encryption_details(browse_files.filename, temp_key)
    except Exception as e:
        status_label.config(text="Encryption failed.", fg="#f44336")
        print(f"Error: {e}")

def decrypt_file(p_word):
    temp_key = p_word.get().strip()
    if not temp_key:
        messagebox.showwarning("Warning", "Please enter a password for decryption.")
        return

    key = temp_key.ljust(43, "s")[:43] + "="
    fernet = Fernet(key)

    try:
        with open(browse_files.filename, 'rb') as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)

        with open(browse_files.filename, 'wb') as dec_file:
            dec_file.write(decrypted)

        status_label.config(text="File decrypted successfully", fg="#4caf50")
    except Exception:
        status_label.config(text="Decryption failed. Incorrect password or file is not encrypted.", fg="#f44336")

def save_encryption_details(filename, password):
    current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("encryption_log.txt", "a") as log_file:
        log_file.write(f"File: {filename}, Password: {password}, Date: {current_date}\n")

def show_controls():
    pass_label.pack(pady=5)
    password.pack(pady=5)
    button_encrypt.pack(pady=10)
    button_decrypt.pack(pady=5)

# UI Elements
main_title = Label(window, text="File Encryptor & Decryptor", bg="#1a1a1d", fg="#e0e0e0", font=("Helvetica", 28, "bold"))
label_file_explorer = Label(window, text="Select a file to encrypt or decrypt", bg="#1a1a1d", fg="#a1a1a1", font=("Helvetica", 16))
pass_label = Label(window, text="Enter password for encryption/decryption:", bg="#1a1a1d", fg="#e0e0e0", font=("Helvetica", 16))
password = Entry(window, show="*", font=("Helvetica", 14), width=30, bg="#333", fg="#e0e0e0", insertbackground="#e0e0e0")

# Button styling with animations
def animate_button(button):
    button.bind("<Enter>", lambda e: button.config(bg="#555"))
    button.bind("<Leave>", lambda e: button.config(bg=button.cget('activebackground')))

button_explore = Button(window, text="Browse File", command=browse_files, width=20, font=("Helvetica", 14, "bold"),
                        bg="#2196f3", fg="#f5f5f5", activebackground="#1976d2", activeforeground="#f5f5f5")
animate_button(button_explore)

button_encrypt = Button(window, text="Encrypt", command=lambda: encrypt_file(password), width=20, font=("Helvetica", 14, "bold"),
                        bg="#4caf50", fg="#f5f5f5", activebackground="#388e3c", activeforeground="#f5f5f5")
animate_button(button_encrypt)

button_decrypt = Button(window, text="Decrypt", command=lambda: decrypt_file(password), width=20, font=("Helvetica", 14, "bold"),
                        bg="#f44336", fg="#f5f5f5", activebackground="#d32f2f", activeforeground="#f5f5f5")
animate_button(button_decrypt)

status_label = Label(window, text="", bg="#1a1a1d", fg="#e0e0e0", font=("Helvetica", 16))

# Pack Widgets in Vertical Layout
main_title.pack(pady=20)
label_file_explorer.pack(pady=10)
button_explore.pack(pady=10)
status_label.pack(pady=20)

# Start main loop
window.mainloop()
