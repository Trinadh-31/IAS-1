import argparse
import hashlib
import os
import socket
from common.ciphers import caesar_encrypt, playfair_encrypt, sdes_decrypt, sdes_encrypt
from common.protocol import recv_bytes, recv_message, send_bytes, send_message

SDES_KEY = "1010000010"
PLAYFAIR_KEY = "MONARCHY"


def choose_algorithm():
    print("\n=== ALM CRYPTO CLIENT ===")
    print("1. Caesar Cipher")
    print("2. Playfair Cipher")
    print("3. S-DES")
    while True:
        choice = input("Choose algorithm (1-3): ").strip()
        if choice in {"1", "2", "3"}:
            return {"1": "CAESAR", "2": "PLAYFAIR", "3": "SDES"}[choice]
        print("Please enter 1, 2, or 3.")


def build_text_request(algorithm):
    plaintext = input("Enter plaintext message: ")
    if algorithm == "CAESAR":
        shift_text = input("Enter Caesar shift [3]: ").strip()
        shift = int(shift_text) if shift_text else 3
        ciphertext = caesar_encrypt(plaintext, shift)
    elif algorithm == "PLAYFAIR":
        ciphertext = playfair_encrypt(plaintext, PLAYFAIR_KEY)
        shift = 3
    else:
        ciphertext = sdes_encrypt(plaintext.encode(), SDES_KEY).hex()
        shift = 3
    print("\n[CLIENT] Encryption message (ciphertext):", ciphertext)
    return {"type": "text_request", "algorithm": algorithm, "plaintext": plaintext, "shift": shift}


def make_1mb_file():
    path = os.path.join(os.getcwd(), "client_1MB_test.txt")
    block = ("ALM S-DES CLIENT FILE TRANSFER DEMO. " * 1024).encode()
    data = (block * ((1024 * 1024 + len(block) - 1) // len(block)))[:1024 * 1024]
    with open(path, "wb") as f:
        f.write(data)
    return path, data


def main():
    parser = argparse.ArgumentParser(description="ALM Crypto Client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    algorithm = choose_algorithm()
    request = build_text_request(algorithm)

    with socket.create_connection((args.host, args.port), timeout=30) as sock:
        send_message(sock, request)
        result = recv_message(sock)
        print("\n=== SERVER RESPONSE ===")
        print("Ciphertext:", result["ciphertext"])
        print("Plaintext :", result["plaintext"])
        print("Decrypted :", result["decrypted"])

        path, data = make_1mb_file()
        cipher = sdes_encrypt(data, SDES_KEY)
        print("\n=== 1 MB CLIENT -> SERVER (S-DES) ===")
        print("Plain bytes :", len(data))
        print("Cipher bytes:", len(cipher))
        print("Plain preview:", data[:128].decode("utf-8", errors="replace"))
        print("Cipher preview:", cipher[:128].hex())
        send_message(sock, {"type": "sdes_file_upload", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        send_bytes(sock, cipher)

        file_result = recv_message(sock)
        print("\n[SERVER] Decrypted 1 MB file:", file_result["size"], "bytes")
        print("[SERVER] Plain SHA-256:", file_result["sha256"])

        send_message(sock, {"type": "ready_for_server_file"})
        recv_message(sock)
        downloaded_cipher = recv_bytes(sock)
        downloaded_plain = sdes_decrypt(downloaded_cipher, SDES_KEY)
        print("\n=== SERVER -> CLIENT (S-DES, 10 KB) ===")
        print("Cipher bytes:", len(downloaded_cipher))
        print("Plain bytes :", len(downloaded_plain))
        print("Cipher preview:", downloaded_cipher[:128].hex())
        print("Plain preview:", downloaded_plain[:128].decode("utf-8", errors="replace"))

        out = os.path.join(os.getcwd(), "server_10KB_received.txt")
        with open(out, "wb") as f:
            f.write(downloaded_plain)
        print("\n[CLIENT] Saved decrypted 10 KB file to:", out)
        print("[CLIENT] SHA-256:", hashlib.sha256(downloaded_plain).hexdigest())
        os.remove(path)


if __name__ == "__main__":
    main()
