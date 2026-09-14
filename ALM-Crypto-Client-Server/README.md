# ALM Active Learning Management - Client/Server Cryptography

Python TCP client/server implementation for the ALM lab/tutorial requirements.

## Included

- Client-side algorithm menu: Caesar Cipher, Playfair Cipher, S-DES.
- Client encrypts a text message and displays ciphertext.
- Server receives the message, displays ciphertext and decrypted plaintext.
- Server sends the result back so both sides can display ciphertext and plaintext.
- S-DES 1 MB client-to-server file transfer.
- S-DES 10 KB server-to-client file transfer.
- Binary-safe length-prefixed TCP protocol.
- Automated tests for all three algorithms.

## Run

Python 3.9+; no third-party packages required.

Terminal 1:

```bash
python server.py
```

Terminal 2:

```bash
python client.py
```

Choose 1, 2, or 3 and enter a plaintext message. The demo then performs the 1 MB and 10 KB S-DES file transfers automatically.

## Tutorial problem 1

The two selected classical algorithms are **Caesar Cipher** and **Playfair Cipher**.

## S-DES note

S-DES is implemented as an educational 8-bit block cipher with a 10-bit key. The file demonstration applies it independently to each byte for lab purposes; this is not a production encryption mode.

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

All tests should pass.
