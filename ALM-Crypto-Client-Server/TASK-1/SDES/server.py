import socket

HOST = "127.0.0.1"
PORT = 5003
KEY = "1010000010"

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


def permute(bits, table): return ''.join(bits[i - 1] for i in table)

def left_shift(bits, n): return bits[n:] + bits[:n]

def generate_keys(key):
    p10 = permute(key, P10)
    l, r = p10[:5], p10[5:]
    l, r = left_shift(l, 1), left_shift(r, 1)
    k1 = permute(l + r, P8)
    l, r = left_shift(l, 2), left_shift(r, 2)
    k2 = permute(l + r, P8)
    return k1, k2

def sbox(bits, box):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(box[row][col], '02b')

def fk(bits, key):
    l, r = bits[:4], bits[4:]
    expanded = permute(r, EP)
    x = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, key))
    x = permute(sbox(x[:4], S0) + sbox(x[4:], S1), P4)
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(l, x)) + r

def encrypt_byte(value):
    k1, k2 = generate_keys(KEY)
    x = fk(permute(format(value, '08b'), IP), k1)
    x = fk(x[4:] + x[:4], k2)
    return int(permute(x, IP_INV), 2)

def decrypt_byte(value):
    k1, k2 = generate_keys(KEY)
    x = fk(permute(format(value, '08b'), IP), k2)
    x = fk(x[4:] + x[:4], k1)
    return int(permute(x, IP_INV), 2)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print("Waiting for client...")

    conn, addr = server.accept()
    with conn:
        plaintext = conn.recv(8192)
        ciphertext = bytes(encrypt_byte(b) for b in plaintext)
        decrypted = bytes(decrypt_byte(b) for b in ciphertext)
        print("Encrypted message:", ciphertext.hex())
        print("Decrypted message:", decrypted.decode(errors='replace'))
        conn.sendall(f"Ciphertext: {ciphertext.hex()}\nPlaintext: {decrypted.decode(errors='replace')}".encode())
