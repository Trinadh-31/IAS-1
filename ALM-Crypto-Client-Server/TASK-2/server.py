import socket
import hashlib

HOST = "127.0.0.1"
PORT = 5004
KEY = "1010000010"

P10=[3,5,2,7,4,10,1,9,8,6]; P8=[6,3,7,4,8,5,10,9]
IP=[2,6,3,1,4,8,5,7]; IP_INV=[4,1,3,5,7,2,8,6]
EP=[4,1,2,3,2,3,4,1]; P4=[2,4,3,1]
S0=[[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
S1=[[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]

def permute(bits,t): return ''.join(bits[i-1] for i in t)
def ls(bits,n): return bits[n:]+bits[:n]
def keys(k):
    x=permute(k,P10); l,r=x[:5],x[5:]; l,r=ls(l,1),ls(r,1); k1=permute(l+r,P8); l,r=ls(l,2),ls(r,2); return k1,permute(l+r,P8)
def sb(x,b): return format(b[int(x[0]+x[3],2)][int(x[1]+x[2],2)],'02b')
def fk(x,k):
    l,r=x[:4],x[4:]; z=''.join(str(int(a)^int(b)) for a,b in zip(permute(r,EP),k)); z=permute(sb(z[:4],S0)+sb(z[4:],S1),P4); return ''.join(str(int(a)^int(b)) for a,b in zip(l,z))+r
def enc(b):
    k1,k2=keys(KEY); x=fk(permute(format(b,'08b'),IP),k1); return int(permute(fk(x[4:]+x[:4],k2),IP_INV),2)
def dec(b):
    k1,k2=keys(KEY); x=fk(permute(format(b,'08b'),IP),k2); return int(permute(fk(x[4:]+x[:4],k1),IP_INV),2)

def recv_all(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(min(65536,n-len(data)))
        if not part: raise ConnectionError('Connection closed')
        data+=part
    return data

with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    server.bind((HOST,PORT)); server.listen(1)
    print('Waiting for client...')
    conn,addr=server.accept()
    with conn:
        header=recv_all(conn,40)
        if header[:3] != b'1MB': raise ValueError('Invalid file header')
        size=int.from_bytes(header[3:7],'big'); expected_hash=header[7:39]
        cipher=recv_all(conn,size)
        plain=bytes(dec(b) for b in cipher)
        print('\nCLIENT -> SERVER')
        print('Ciphertext file size:',len(cipher),'bytes')
        print('Plaintext file size:',len(plain),'bytes')
        print('Ciphertext preview:',cipher[:64].hex())
        print('Plaintext preview:',plain[:64])
        print('SHA-256:',hashlib.sha256(plain).hexdigest())
        print('Integrity verified:',hashlib.sha256(plain).digest()==expected_hash)
        conn.sendall(b'1 MB file received and decrypted successfully')

        plain10=bytes((ord('A') + (i % 26) for i in range(10*1024)))
        cipher10=bytes(enc(b) for b in plain10)
        conn.sendall(b'10KB'+len(cipher10).to_bytes(4,'big')+cipher10)
        print('\nSERVER -> CLIENT')
        print('Plaintext file size:',len(plain10),'bytes')
        print('Ciphertext preview:',cipher10[:64].hex())
