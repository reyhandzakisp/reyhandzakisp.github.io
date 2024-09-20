import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Reyhan Dzaki Sheva P. / 4611421122

# Vigenere Cipher
def vigenere_enkripsi(plainteks, key):
    key = key.upper()
    key_length = len(key)
    cipherteks = ""
    for i, char in enumerate(plainteks):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            if char.isupper():
                cipherteks += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                cipherteks += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            cipherteks += char
    return cipherteks

def vigenere_dekripsi(cipherteks, key):
    key = key.upper()
    key_length = len(key)
    plainteks = ""
    for i, char in enumerate(cipherteks):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            if char.isupper():
                plainteks += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                plainteks += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            plainteks += char
    return plainteks

# Playfair Cipher
def prepare_text(text):
    text = text.upper().replace('J', 'I')
    prepared_text = ""
    i = 0
    while i < len(text):
        if text[i].isalpha():
            char1 = text[i]
            char2 = text[i + 1] if i + 1 < len(text) and text[i + 1].isalpha() else 'X'
            if char1 == char2:
                prepared_text += char1 + 'X'
                i += 1
            else:
                prepared_text += char1 + char2
                i += 2
        else:
            i += 1
    if len(prepared_text) % 2 != 0:
        prepared_text += 'X'
    return prepared_text

def generate_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    matrix = []
    for char in key:
        if char not in matrix and char.isalpha():
            matrix.append(char)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in matrix:
            matrix.append(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col

def playfair_encrypt(plainteks, key):
    matrix = generate_playfair_matrix(key)
    plainteks = prepare_text(plainteks)
    cipherteks = ""
    for i in range(0, len(plainteks), 2):
        row1, col1 = find_position(matrix, plainteks[i])
        row2, col2 = find_position(matrix, plainteks[i+1])
        if row1 is None or row2 is None:
            continue
        if row1 == row2:
            cipherteks += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            cipherteks += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            cipherteks += matrix[row1][col2] + matrix[row2][col1]
    return cipherteks

def playfair_decrypt(cipherteks, key):
    matrix = generate_playfair_matrix(key)
    plainteks = ""
    for i in range(0, len(cipherteks), 2):
        row1, col1 = find_position(matrix, cipherteks[i])
        row2, col2 = find_position(matrix, cipherteks[i+1])
        if row1 is None or row2 is None:
            continue
        if row1 == row2:
            plainteks += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plainteks += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            plainteks += matrix[row1][col2] + matrix[row2][col1]
    return plainteks

# Hill Cipher
def hill_encrypt(plainteks, key_matrix):
    n = len(key_matrix)
    plainteks = plainteks.replace(" ", "").upper()
    while len(plainteks) % n != 0:
        plainteks += 'X'

    cipherteks = ""
    for i in range(0, len(plainteks), n):
        block = plainteks[i:i+n]
        block_vector = [ord(c) - ord('A') for c in block]
        result_vector = np.dot(key_matrix, block_vector) % 26
        cipherteks += ''.join(chr(num + ord('A')) for num in result_vector)
    return cipherteks

def hill_decrypt(cipherteks, key_matrix):
    n = len(key_matrix)
    cipherteks = cipherteks.replace(" ", "").upper()
    inv_key_matrix = np.linalg.inv(key_matrix)
    inv_key_matrix = np.round(inv_key_matrix * np.linalg.det(key_matrix)).astype(int) % 26

    plainteks = ""
    for i in range(0, len(cipherteks), n):
        block = cipherteks[i:i+n]
        block_vector = [ord(c) - ord('A') for c in block]
        result_vector = np.dot(inv_key_matrix, block_vector) % 26
        plainteks += ''.join(chr(int(num) + ord('A')) for num in result_vector)
    return plainteks

# GUI
class Kriptografi:
    def __init__(self, root):
        self.root = root
        self.root.title("Kriptografi")

        self.message_label = tk.Label(root, text="Input Pesan:")
        self.message_label.pack()

        self.message_text = tk.Text(root, height=10, width=50)
        self.message_text.pack()

        self.key_label = tk.Label(root, text="Input Kunci (Minimal 12 karakter):")
        self.key_label.pack()

        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.pack()

        self.encrypt_button = tk.Button(root, text="Enkripsi", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Dekripsi", command=self.decrypt_message)
        self.decrypt_button.pack()

        self.result_label = tk.Label(root, text="Hasil:")
        self.result_label.pack()

        self.result_text = tk.Text(root, height=10, width=50)
        self.result_text.pack()

    def encrypt_message(self):
        key = self.key_entry.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Panjang kunci minimal 12 karakter!")
            return

        message = self.message_text.get("1.0", tk.END).strip()

        if selected_cipher.get() == "Vigenere":
            result = vigenere_enkripsi(message, key)
        elif selected_cipher.get() == "Playfair":
            result = playfair_encrypt(message, key)
        else:
            key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
            result = hill_encrypt(message, key_matrix)

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)

    def decrypt_message(self):
        key = self.key_entry.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Panjang kunci minimal 12 karakter!")
            return

        message = self.message_text.get("1.0", tk.END).strip()

        if selected_cipher.get() == "Vigenere":
            result = vigenere_dekripsi(message, key)
        elif selected_cipher.get() == "Playfair":
            result = playfair_decrypt(message, key)
        else:
            key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
            result = hill_decrypt(message, key_matrix)

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)

# Inisialisasi
root = tk.Tk()
selected_cipher = tk.StringVar(value="Vigenere")

vigenere_rb = tk.Radiobutton(root, text="Vigenere Cipher", variable=selected_cipher, value="Vigenere")
vigenere_rb.pack()

playfair_rb = tk.Radiobutton(root, text="Playfair Cipher", variable=selected_cipher, value="Playfair")
playfair_rb.pack()

hill_rb = tk.Radiobutton(root, text="Hill Cipher", variable=selected_cipher, value="Hill")
hill_rb.pack()

app = Kriptografi(root)
root.mainloop()
