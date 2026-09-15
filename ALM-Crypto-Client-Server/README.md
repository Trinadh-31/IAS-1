# ALM - Active Learning Management

This project is organized in the same task-oriented style as the reference repository.

## TASK-1

### Caesar Cipher
- `TASK-1/Caesar Cipher/Client.py`
- `TASK-1/Caesar Cipher/Server.py`

### Playfair Cipher
- `TASK-1/Playfair Cipher/Client.py`
- `TASK-1/Playfair Cipher/Server.py`

### S-DES
- `TASK-1/SDES/client.py`
- `TASK-1/SDES/server.py`
- `TASK-1/SDES/files/`

## TASK-2

S-DES file transfer:
- `TASK-2/client.py` — sends a 1 MB file to the server and receives the 10 KB file.
- `TASK-2/server.py` — receives/decrypts the 1 MB file and sends the encrypted 10 KB file back.
- `TASK-2/files/` — file-transfer workspace.

## Run

Start the server first, then the client, from each task folder.

```bash
python Server.py
python Client.py
```

For S-DES and TASK-2:

```bash
python server.py
python client.py
```
