# PROJECT-STEGANOGRAPHY-USING-AES-WITH-GUI


Image Steganography with AES Encryption

Overview:

This project implements Image Steganography using Least Significant Bit (LSB) encoding combined with AES encryption to securely hide and extract messages from images. It features a modern GUI built with ttkbootstrap, making it user-friendly for both desktop and mobile views.

Features:

✔️ Hide a Secret Message: Encrypts and embeds text within an image.

✔️ Extract a Hidden Message: Retrieves and decrypts the hidden text from an image.

✔️ AES-128 Encryption: Uses a 16-character secret key to ensure message security.

✔️ Modern GUI: Built with ttkbootstrap for an enhanced user experience.

✔️ Supports PNG, JPEG, and JPG formats.

Installation:
pip install opencv-python numpy ttkbootstrap pillow pycryptodome

Usage:

1. Hide a Message in an Image ( GUI )

Run the program:

python encryption.py
Enter a secret message and a 16-character secret key.
Select an image to embed the message.
Save the encoded image with the hidden message.

2. Extract a Message from an Image ( GUI )

Run the program:

python second_half.py
Select the encoded image containing the hidden message.
Enter the correct 16-character secret key.
The extracted message will be displayed in the output box.



3.python steganography.py

Hide a Message in an Image ( GUI )  and Extract a Message from an Image ( GUI ) 
Run the program:

Enter a secret message and a 16-character secret key.
Select an image to embed the message.
Save the encoded image with the hidden message

Select the encoded image containing the hidden message.
Enter the correct 16-character secret key.
The extracted message will be displayed in the output box


Technologies Used:

Python – Core programming language.

OpenCV (cv2) – Image processing and modification.
NumPy – Handling pixel-level data in images.
ttkbootstrap – Modern GUI styling.
Pillow (PIL) – Image handling in the GUI.
PyCryptodome – AES encryption for message security.

Security Considerations:

Ensure your secret key is exactly 16 characters for AES encryption.
Use high-resolution images for better security and minimal distortion.
If the decryption fails, verify the correct key was used during extraction.


Author: 

Developed by [YASHWANTH PANCHAGIRI]
