import argparse
import hashlib
import socket
from common.ciphers import caesar_decrypt, caesar_encrypt, playfair_decrypt, playfair_encrypt, sdes_decrypt, sdes_encrypt
from common.protocol import recv_bytes, recv_message, send_bytes, send_message

HOST = "0.0.0.0"
PORT = 5000
SDES_KEY = "1010000010"
PLAYFAIR_KEY = "MONARCHY"


def handle_text(payload):
    algorithm = payload["algorithm"]
    plaintext = payload["plaintext"]
    if algorithm == "CAESAR":
        shift = int(payload.get("shift", 3))
        ciphertext = caesar_encrypt(plaintext, shift)
        decrypted = caesar_decrypt(ciphertext, shift)
    elif algorithm == "PLAYFAIR":
        ciphertext = playfair_encrypt(plaintext, PLAYFAIR_KEY)
        decrypted = playfair_decrypt(ciphertext, PLAYFAIR_KEY)
    elif algorithm == "SDES":
        raw = plaintext.encode("utf-8")
        ciphertext = sdes_encrypt(raw, SDES_KEY).hex()
        decrypted = sdes_decrypt(bytes.fromhex(ciphertext), SDES_KEY).decode("utf-8")
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return {"type": "text_result", "algorithm": algorithm, "plaintext": plaintext,
            "ciphertext": ciphertext, "decrypted": decrypted}


def serve_client(conn):
    print(f"[+] Client connected: {conn.getpeername()}")
    request = recv_message(conn)
    if request.get("type") != "text_request":
        raise ValueError("Expected text_request.")
    result = handle_text(request)
    print("\n=== CLIENT -> SERVER ===")
    print("Algorithm :", result["algorithm"])
    print("Ciphertext:", result["ciphertext"])
    print("Plaintext :", result["decrypted"])
    send_message(conn, result)

    request = recv_message(conn)
    if request.get("type") != "sdes_file_upload":
        raise ValueError("Expected sdes_file_upload.")
    ciphertext = recv_bytes(conn)
    plaintext = sdes_decrypt(ciphertext, SDES_KEY)
    digest = hashlib.sha256(plaintext).hexdigest()
    print("\n=== 1 MB CLIENT -> SERVER (S-DES) ===")
    print("Cipher bytes:", len(ciphertext))
    print("Plain bytes :", len(plaintext))
    print("SHA-256 (plain):", digest)
    send_message(conn, {"type": "file_result", "direction": "client_to_server",
                        "size": len(plaintext), "plaintext_preview": plaintext[:128].decode("utf-8", errors="replace"),
                        "ciphertext_preview": ciphertext[:128].hex(), "sha256": digest})

    response = recv_message(conn)
    if response.get("type") != "ready_for_server_file":
        raise ValueError("Expected ready_for_server_file.")
    server_plaintext = (b"SERVER -> CLIENT S-DES DEMO\n" * 400)[:10 * 1024]
    server_cipher = sdes_encrypt(server_plaintext, SDES_KEY)
    print("\n=== SERVER -> CLIENT (S-DES, 10 KB) ===")
    print("Plain bytes :", len(server_plaintext))
    print("Cipher bytes:", len(server_cipher))
    print("Plain preview:", server_plaintext[:128].decode("utf-8", errors="replace"))
    print("Cipher preview:", server_cipher[:128].hex())
    send_message(conn, {"type": "sdes_file_download", "algorithm": "SDES", "size": len(server_plaintext)})
    send_bytes(conn, server_cipher)
    print("[+] Demo complete.")


def main():
    parser = argparse.ArgumentParser(description="ALM Crypto Server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(1)
        print(f"[*] Listening on {args.host}:{args.port}")
        conn, _ = server.accept()
        with conn:
            serve_client(conn)


if __name__ == "__main__":
    main()
