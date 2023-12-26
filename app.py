from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        text = request.form["text"]
        encryption_type = request.form["encryption_type"]

        if encryption_type == "AES":
            # Generate an AES key and IV
            aes_key = b'secretkey1234567'
            # Generate a random 16-byte IV
            iv = secrets.token_bytes(16)
            # Encrypt using AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
            # Decrypt using AES
            decryptor = cipher.decryptor()
            decrypted_text = (decryptor.update(encrypted_text) + decryptor.finalize()).decode()

            ###################################################################################

            # Encrypt C = (P + K) mod 26
            # Decrypt P = (C - K) mod 26
        elif encryption_type == "Caesar":
            shift = 3
            def caesar_cipher(text, shift):
                result = []
                for char in text:
                    if char.isalpha():
                        base = ord('A') if char.isupper() else ord('a')
                        result.append(chr((ord(char) - base + shift) % 26 + base))
                    else:
                        result.append(char)
                return ''.join(result)

            encrypted_text = caesar_cipher(text, shift)
            decrypted_text = caesar_cipher(encrypted_text, -shift)
        else:
            return render_template("index.html", error="Invalid encryption type")

        return render_template("index.html", text=text, encrypted_text=encrypted_text, decrypted_text=decrypted_text, encryption_type=encryption_type)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
