import socket

HOST = "127.0.0.1"
PORT = 5002
KEY = "MONARCHY"


def build_matrix(key):
    chars = []
    for ch in (key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ").upper():
        ch = 'I' if ch == 'J' else ch
        if ch.isalpha() and ch not in chars:
            chars.append(ch)
    return [chars[i:i + 5] for i in range(0, 25, 5)]


def prepare(text):
    text = ''.join(ch for ch in text.upper() if ch.isalpha()).replace('J', 'I')
    result = ''
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else 'X'
        result += a + ('X' if a == b else b)
        i += 1 if a == b else 2
    if len(result) % 2:
        result += 'X'
    return result


def playfair_encrypt(text, key):
    matrix = build_matrix(key)
    pos = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    text = prepare(text)
    out = ''
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out += matrix[ra][(ca + 1) % 5] + matrix[rb][(cb + 1) % 5]
        elif ca == cb:
            out += matrix[(ra + 1) % 5][ca] + matrix[(rb + 1) % 5][cb]
        else:
            out += matrix[ra][cb] + matrix[rb][ca]
    return out


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print("Waiting for client...")

    conn, addr = server.accept()
    with conn:
        plaintext = conn.recv(4096).decode()
        ciphertext = playfair_encrypt(plaintext, KEY)
        print("Client plaintext:", plaintext)
        print("Client ciphertext:", ciphertext)
        conn.sendall(f"Ciphertext: {ciphertext}\nPlaintext: {plaintext}".encode())
