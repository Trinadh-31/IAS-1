import unittest
from common.ciphers import caesar_encrypt, caesar_decrypt, playfair_encrypt, playfair_decrypt, sdes_encrypt, sdes_decrypt

class TestCiphers(unittest.TestCase):
    def test_caesar(self):
        self.assertEqual(caesar_encrypt("Hello World!",3),"Khoor Zruog!")
        self.assertEqual(caesar_decrypt("Khoor Zruog!",3),"Hello World!")
    def test_playfair(self):
        c=playfair_encrypt("instruments","monarchy")
        self.assertEqual(c,"GATLMZCLRQXA")
        self.assertEqual(playfair_decrypt(c,"monarchy"),"INSTRUMENTSX")
    def test_sdes_vector(self):
        key="1010000010"; plain=bytes([0x6F]); c=sdes_encrypt(plain,key)
        self.assertEqual(c,bytes.fromhex("2f")); self.assertEqual(sdes_decrypt(c,key),plain)
    def test_sdes_roundtrip(self):
        data=bytes(range(256))*64; c=sdes_encrypt(data,"1010000010")
        self.assertEqual(sdes_decrypt(c,"1010000010"),data)

if __name__ == "__main__": unittest.main()
