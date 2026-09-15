import socket

HOST = "127.0.0.1"
PORT = 5001


def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch
    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print("Waiting for client...")

    conn, addr = server.accept()
    with conn:
        data = conn.recv(4096).decode()
        shift, plaintext = data.split("|", 1)
        shift = int(shift)

        ciphertext = caesar_encrypt(plaintext, shift)
        decrypted = caesar_decrypt(ciphertext, shift)

        print("Client ciphertext:", ciphertext)
        print("Client plaintext:", plaintext)
        print("Decrypted message:", decrypted)

        conn.sendall(f"{ciphertext}|{decrypted}".encode())
