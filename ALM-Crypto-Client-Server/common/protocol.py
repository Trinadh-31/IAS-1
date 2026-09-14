import json
import socket
import struct

HEADER = struct.Struct("!I")

def send_message(sock, payload):
    data=json.dumps(payload,ensure_ascii=False).encode("utf-8")
    sock.sendall(HEADER.pack(len(data))+data)

def recv_message(sock):
    header=_recv_exact(sock,HEADER.size)
    if not header: raise ConnectionError("Connection closed while reading message header.")
    (size,)=HEADER.unpack(header)
    if size>64*1024*1024: raise ValueError("Message is too large.")
    return json.loads(_recv_exact(sock,size).decode("utf-8"))

def send_bytes(sock,data): sock.sendall(HEADER.pack(len(data))+data)

def recv_bytes(sock):
    header=_recv_exact(sock,HEADER.size)
    if not header: raise ConnectionError("Connection closed during binary transfer.")
    (size,)=HEADER.unpack(header); return _recv_exact(sock,size)

def _recv_exact(sock,n):
    chunks=[]; remaining=n
    while remaining:
        chunk=sock.recv(remaining)
        if not chunk: raise ConnectionError("Connection closed during transfer.")
        chunks.append(chunk); remaining-=len(chunk)
    return b"".join(chunks)
