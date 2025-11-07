import streamlit as st
import sqlite3
import blake3
from Crypto.Cipher import AES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import pywt
from PIL import Image
import numpy as np
import io

# ==============================
# 📦 INISIALISASI DATABASE
# ==============================
def init_db():
    conn = sqlite3.connect('secure_system.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            data BLOB NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ==============================
# 🔐 LOGIN & REGISTER (BLAKE3)
# ==============================
def register_user(username, password):
    conn = sqlite3.connect('secure_system.db')
    cursor = conn.cursor()
    password_hash = blake3.blake3(password.encode()).hexdigest()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        st.success("✅ Registrasi berhasil! Silakan login.")
    except sqlite3.IntegrityError:
        st.error("❌ Username sudah digunakan.")
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('secure_system.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user and user[0] == blake3.blake3(password.encode()).hexdigest():
        return True
    else:
        return False

# ==============================
# 💾 AES-GCM (untuk Database)
# ==============================
def encrypt_aes_gcm(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_aes_gcm(enc_data, key):
    try:
        raw = base64.b64decode(enc_data)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception:
        return "❌ Dekripsi gagal! Coba periksa kembali kunci atau data."

# ==============================
# 🔤 Caesar + CBC (Text)
# ==============================
def caesar_encrypt(text, shift):
    return ''.join(chr((ord(c) + shift) % 256) for c in text)

def caesar_decrypt(text, shift):
    return ''.join(chr((ord(c) - shift) % 256) for c in text)

def cbc_encrypt_caesar(text, key):
    iv = ord(key[0]) % 256
    result = ""
    for char in text:
        iv = (ord(char) + iv) % 256
        result += chr(iv)
    return base64.b64encode(result.encode()).decode()

def cbc_decrypt_caesar(enc_text, key):
    text = base64.b64decode(enc_text).decode()
    iv = ord(key[0]) % 256
    result = ""
    for char in text:
        temp = ord(char)
        result += chr((temp - iv) % 256)
        iv = temp
    return result

# ==============================
# 📁 ARC4 FILE ENCRYPTION
# ==============================
def encrypt_file_arc4(file_data, key):
    cipher = ARC4.new(key)
    encrypted_data = cipher.encrypt(file_data)
    return encrypted_data

def decrypt_file_arc4(enc_data, key):
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(enc_data)
    return decrypted_data

# ==============================
# 🖼️ DWT STEGANOGRAPHY
# ==============================
def embed_dwt(image, secret_text):
    img = np.array(image.convert("L"), dtype=np.float32)
    coeffs = pywt.dwt2(img, 'haar')
    cA, (cH, cV, cD) = coeffs
    secret_bin = ''.join(format(ord(ch), '08b') for ch in secret_text)
    flat = cD.flatten()
    for i in range(min(len(secret_bin), len(flat))):
        flat[i] = int(flat[i]) & ~1 | int(secret_bin[i])
    cD = flat.reshape(cD.shape)
    stego_img = pywt.idwt2((cA, (cH, cV, cD)), 'haar')
    stego_img = Image.fromarray(np.uint8(stego_img))
    return stego_img

def extract_dwt(stego_image, length):
    img = np.array(stego_image.convert("L"), dtype=np.float32)
    coeffs = pywt.dwt2(img, 'haar')
    cA, (cH, cV, cD) = coeffs
    flat = cD.flatten()
    bits = [str(int(x) & 1) for x in flat[:length*8]]
    chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

# ==============================
# 🌐 DASHBOARD (SETELAH LOGIN)
# ==============================
def dashboard(username):
    st.title(f"👮 Sistem Kriptografi & Steganografi Bukti Digital")
    st.caption(f"Login sebagai: **{username}**")

    menu = st.sidebar.radio("Pilih Modul:", [
        "AES-GCM (Database)",
        "Caesar + CBC (Text)",
        "ARC4 (File)",
        "DWT (Steganografi)",
        "Logout"
    ])

    # ====== AES-GCM ======
    if menu == "AES-GCM (Database)":
        st.subheader("🔒 Enkripsi & Dekripsi Data (AES-GCM)")
        key = st.text_input("Masukkan kunci (16 karakter):")
        text = st.text_area("Masukkan teks:")
        if st.button("Enkripsi"):
            if len(key) == 16:
                enc = encrypt_aes_gcm(text, key.encode())
                st.text_area("Hasil Enkripsi:", enc)
            else:
                st.warning("⚠️ Kunci harus tepat 16 karakter.")
        if st.button("Dekripsi"):
            if len(key) == 16:
                dec = decrypt_aes_gcm(text, key.encode())
                st.text_area("Hasil Dekripsi:", dec)
            else:
                st.warning("⚠️ Kunci harus tepat 16 karakter.")

    # ====== Caesar + CBC ======
    elif menu == "Caesar + CBC (Text)":
        st.subheader("🔤 Enkripsi Pesan (Caesar + CBC)")
        key = st.text_input("Masukkan kunci minimal 1 huruf:")
        text = st.text_area("Pesan:")
        if st.button("Enkripsi Text"):
            st.text_area("Hasil:", cbc_encrypt_caesar(text, key))
        if st.button("Dekripsi Text"):
            st.text_area("Hasil:", cbc_decrypt_caesar(text, key))

    # ====== ARC4 ======
    elif menu == "ARC4 (File)":
        st.subheader("📁 Enkripsi / Dekripsi File (ARC4)")
        key = st.text_input("Masukkan kunci ARC4:")
        file = st.file_uploader("Pilih file:")
        if file and key:
            if st.button("Enkripsi File"):
                enc_data = encrypt_file_arc4(file.read(), key.encode())
                st.download_button("💾 Download File Terenkripsi", enc_data, file_name="encrypted.bin")
            if st.button("Dekripsi File"):
                dec_data = decrypt_file_arc4(file.read(), key.encode())
                st.download_button("💾 Download File Terdekripsi", dec_data, file_name="decrypted.bin")

    # ====== DWT ======
    elif menu == "DWT (Steganografi)":
        st.subheader("🖼️ Steganografi DWT (Sembunyikan Teks di Gambar)")
        image = st.file_uploader("Pilih gambar (PNG/JPG):", type=["png", "jpg"])
        secret = st.text_input("Masukkan teks rahasia:")
        if image and secret:
            if st.button("Sembunyikan Pesan"):
                img = Image.open(image)
                stego_img = embed_dwt(img, secret)
                buf = io.BytesIO()
                stego_img.save(buf, format="PNG")
                st.image(stego_img, caption="Gambar Berisi Pesan Rahasia")
                st.download_button("💾 Download Gambar Stego", buf.getvalue(), file_name="stego.png", mime="image/png")
        st.divider()
        st.subheader("🔍 Ekstraksi Pesan dari Gambar")
        stego = st.file_uploader("Pilih gambar stego:", type=["png", "jpg"])
        length = st.number_input("Panjang teks:", min_value=1, step=1)
        if st.button("Ekstrak Pesan"):
            if stego:
                img = Image.open(stego)
                st.success(f"Pesan: {extract_dwt(img, int(length))}")

    elif menu == "Logout":
        st.session_state["logged_in"] = False
        st.rerun()

# ==============================
# 🔑 HALAMAN LOGIN
# ==============================
def login_page():
    st.title("🔐 Sistem Keamanan Bukti Digital")
    st.caption("Gunakan akun Anda untuk mengakses sistem")

    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if authenticate_user(username, password):
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.success("✅ Login berhasil!")
                st.rerun()
            else:
                st.error("❌ Username atau password salah.")

    with tab2:
        new_user = st.text_input("Buat Username")
        new_pass = st.text_input("Buat Password", type="password")
        if st.button("Daftar"):
            register_user(new_user, new_pass)

# ==============================
# 🚀 MAIN APP
# ==============================
def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if not st.session_state["logged_in"]:
        login_page()
    else:
        dashboard(st.session_state["username"])

if __name__ == "__main__":
    main()
