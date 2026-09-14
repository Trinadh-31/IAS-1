import string
from typing import List, Tuple

ALPHABET = string.ascii_uppercase

def _shift_char(ch: str, shift: int) -> str:
    if ch.isalpha():
        base = ord("A") if ch.isupper() else ord("a")
        return chr((ord(ch) - base + shift) % 26 + base)
    return ch

def caesar_encrypt(text: str, shift: int) -> str:
    return "".join(_shift_char(ch, shift) for ch in text)

def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)

def _playfair_key_square(key: str) -> List[str]:
    key = "".join(ch for ch in key.upper() if ch.isalpha()).replace("J", "I")
    seen, chars = set(), []
    for ch in key + ALPHABET:
        ch = "I" if ch == "J" else ch
        if ch not in seen and ch != "J":
            seen.add(ch); chars.append(ch)
    return chars

def _playfair_prepare(text: str) -> str:
    text = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
    out, i = [], 0
    while i < len(text):
        a = text[i]; b = text[i + 1] if i + 1 < len(text) else "X"
        if a == b:
            out.extend([a, "X"]); i += 1
        else:
            out.extend([a, b]); i += 2
    if len(out) % 2: out.append("X")
    return "".join(out)

def playfair_encrypt(text: str, key: str) -> str:
    square = _playfair_key_square(key); pos = {ch: divmod(i, 5) for i, ch in enumerate(square)}
    prepared = _playfair_prepare(text); result = []
    for i in range(0, len(prepared), 2):
        a, b = prepared[i:i+2]; ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb: result += [square[ra*5+(ca+1)%5], square[rb*5+(cb+1)%5]]
        elif ca == cb: result += [square[((ra+1)%5)*5+ca], square[((rb+1)%5)*5+cb]]
        else: result += [square[ra*5+cb], square[rb*5+ca]]
    return "".join(result)

def playfair_decrypt(text: str, key: str) -> str:
    square = _playfair_key_square(key); pos = {ch: divmod(i, 5) for i, ch in enumerate(square)}
    text = "".join(ch for ch in text.upper() if ch.isalpha()).replace("J", "I")
    if len(text) % 2: raise ValueError("Playfair ciphertext must have even length.")
    result = []
    for i in range(0, len(text), 2):
        a, b = text[i:i+2]; ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb: result += [square[ra*5+(ca-1)%5], square[rb*5+(cb-1)%5]]
        elif ca == cb: result += [square[((ra-1)%5)*5+ca], square[((rb-1)%5)*5+cb]]
        else: result += [square[ra*5+cb], square[rb*5+ca]]
    return "".join(result)

P10=(3,5,2,7,4,10,1,9,8,6); P8=(6,3,7,4,8,5,10,9); P4=(2,4,3,1)
IP=(2,6,3,1,4,8,5,7); IP_INV=(4,1,3,5,7,2,8,6); EP=(4,1,2,3,2,3,4,1)
S0=((1,0,3,2),(3,2,1,0),(0,2,1,3),(3,1,3,2)); S1=((0,1,2,3),(2,0,1,3),(3,0,1,0),(2,1,0,3))

def _perm(bits, table): return "".join(bits[i-1] for i in table)
def _left_shift(bits, n): n%=len(bits); return bits[n:]+bits[:n]

def sdes_key_schedule(key10):
    if len(key10)!=10 or any(c not in "01" for c in key10): raise ValueError("S-DES key must be 10 bits.")
    p=_perm(key10,P10); l,r=p[:5],p[5:]; l,r=_left_shift(l,1),_left_shift(r,1); k1=_perm(l+r,P8); l,r=_left_shift(l,2),_left_shift(r,2); k2=_perm(l+r,P8); return k1,k2

def _sbox(bits4, box):
    row=int(bits4[0]+bits4[3],2); col=int(bits4[1:3],2); return f"{box[row][col]:02b}"

def _f_k(bits8, subkey):
    left,right=bits8[:4],bits8[4:]; mixed=f"{int(_perm(right,EP),2)^int(subkey,2):08b}"; s=_sbox(mixed[:4],S0)+_sbox(mixed[4:],S1); return f"{int(left,2)^int(_perm(s,P4),2):04b}"+right

def sdes_encrypt_block(bits8,key10):
    if len(bits8)!=8 or any(c not in "01" for c in bits8): raise ValueError("S-DES block must be 8 bits.")
    k1,k2=sdes_key_schedule(key10); s=_perm(bits8,IP); s=_f_k(s,k1); s=s[4:]+s[:4]; return _perm(_f_k(s,k2),IP_INV)

def sdes_decrypt_block(bits8,key10):
    k1,k2=sdes_key_schedule(key10); s=_perm(bits8,IP); s=_f_k(s,k2); s=s[4:]+s[:4]; return _perm(_f_k(s,k1),IP_INV)

def sdes_encrypt(data,key10): return bytes(int(sdes_encrypt_block(f"{b:08b}",key10),2) for b in data)
def sdes_decrypt(data,key10): return bytes(int(sdes_decrypt_block(f"{b:08b}",key10),2) for b in data)
