import cv2
import numpy as np
import ttkbootstrap as ttk
from ttkbootstrap import Style
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
import base64
import os

def decrypt_message(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode('utf-8').strip()
    return decrypted_text

def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)

def extract_message():
    file_path = filedialog.askopenfilename(title="Select Encrypted Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return

    img = cv2.imread(file_path)
    if img is None:
        messagebox.showerror("Error", "Could not open image")
        return

    binary_msg = ""
    h, w, _ = img.shape

    for row in range(h):
        for col in range(w):
            for color in range(3):
                binary_msg += str(img[row, col, color] & 1)

    binary_msg = binary_msg.split('1111111111111110')[0]  
    if not binary_msg:
        messagebox.showerror("Error", "No hidden message found")
        return

    extracted_text = binary_to_text(binary_msg)
    secret_key = key_entry.get()
    
    if not secret_key or len(secret_key) != 16:
        messagebox.showerror("Error", "Enter the correct 16-character secret key to decrypt")
        return

    try:
        decrypted_text = decrypt_message(extracted_text, secret_key)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decrypted_text)
    except:
        messagebox.showerror("Error", "Decryption failed. Check your key.")

# GUI Setup
root = ttk.Window(themename="cosmo")
root.title("Image Steganography")
root.geometry("600x500")
root.resizable(False, False)

bg_image_path = "background.jpg"
if os.path.exists(bg_image_path):
    bg_image = Image.open(bg_image_path)
    bg_image = bg_image.resize((600, 500), Image.LANCZOS)
    bg_photo = ImageTk.PhotoImage(bg_image)
    bg_label = ttk.Label(root, image=bg_photo)
    bg_label.place(relwidth=1, relheight=1)

frame = ttk.Frame(root, padding=15, bootstyle="light")
frame.pack(pady=20, padx=20, fill="both", expand=True)

key_label = ttk.Label(frame, text="Enter 16-char Secret Key:", font=("Arial", 12, "bold"))
key_label.pack()

key_entry = ttk.Entry(frame, width=40, font=("Arial", 12), show="*")
key_entry.pack(pady=5)

extract_button = ttk.Button(frame, text="Extract Message", command=extract_message, bootstyle="success")
extract_button.pack(pady=5)

output_label = ttk.Label(frame, text="Extracted Message:", font=("Arial", 12, "bold"))
output_label.pack()

output_text = ttk.Text(frame, height=4, width=40, font=("Arial", 12))
output_text.pack(pady=5)

root.mainloop()
