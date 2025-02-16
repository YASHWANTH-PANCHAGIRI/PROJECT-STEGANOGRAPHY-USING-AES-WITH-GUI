import cv2
import numpy as np
import ttkbootstrap as ttk
from ttkbootstrap import Style
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
import base64
import os

def pad_message(message):
    while len(message) % 16 != 0:
        message += ' '
    return message

def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad_message(message).encode('utf-8'))
    return base64.b64encode(encrypted_text).decode('utf-8')

def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def hide_message():
    file_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return

    img = cv2.imread(file_path)
    if img is None:
        messagebox.showerror("Error", "Could not open image")
        return

    secret_message = text_entry.get()
    secret_key = key_entry.get()
    if not secret_message or not secret_key:
        messagebox.showerror("Error", "Please enter a message and a key")
        return
    
    if len(secret_key) != 16:
        messagebox.showerror("Error", "Secret key must be exactly 16 characters")
        return

    encrypted_msg = encrypt_message(secret_message, secret_key)
    binary_msg = text_to_binary(encrypted_msg) + '1111111111111110'  
    h, w, _ = img.shape

    if len(binary_msg) > h * w * 3:
        messagebox.showerror("Error", "Message too long for image")
        return

    binary_index = 0
    for row in range(h):
        for col in range(w):
            for color in range(3):
                if binary_index < len(binary_msg):
                    img[row, col, color] = (img[row, col, color] & 254) | int(binary_msg[binary_index])
                    binary_index += 1
                else:
                    break

    save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if save_path:
        cv2.imwrite(save_path, img)
        messagebox.showinfo("Success", f"Message hidden in {save_path}")

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

label = ttk.Label(frame, text="Enter Secret Message:", font=("Arial", 12, "bold"))
label.pack()

text_entry = ttk.Entry(frame, width=40, font=("Arial", 12))
text_entry.pack(pady=5)

key_label = ttk.Label(frame, text="Enter 16-char Secret Key:", font=("Arial", 12, "bold"))
key_label.pack()

key_entry = ttk.Entry(frame, width=40, font=("Arial", 12), show="*")
key_entry.pack(pady=5)

hide_button = ttk.Button(frame, text="Hide Message", command=hide_message, bootstyle="primary")
hide_button.pack(pady=5)

root.mainloop()
