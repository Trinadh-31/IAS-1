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


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))

    text = input("Enter message: ")
    shift = int(input("Enter shift: "))

    cipher = caesar_encrypt(text, shift)
    print("Encrypted message:", cipher)

    client.sendall(f"{shift}|{text}".encode())
    response = client.recv(4096).decode()

    cipher_text, plain_text = response.split("|", 1)
    print("Server ciphertext:", cipher_text)
    print("Server plaintext:", plain_text)
