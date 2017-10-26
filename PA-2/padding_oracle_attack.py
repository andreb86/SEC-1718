import sys
import os
from oracle import encrypt, is_padding_ok, BLOCK_SIZE

messages = (b'Attack at dawn', b'', b'Giovanni',
            b"In symmetric cryptography, the padding oracle attack can be applied to the CBC mode of operation," +
            b"where the \"oracle\" (usually a server) leaks data about whether the padding of an encrypted " +
            b"message is correct or not. Such data can allow attackers to decrypt (and sometimes encrypt) " +
            b"messages through the oracle using the oracle's key, without knowing the encryption key")


def attack(ciphertext: bytes):
    cleartext = bytearray(len(ciphertext)-BLOCK_SIZE)
    for i, b in enumerate(ciphertext[-BLOCK_SIZE::-1]):
        for guess in range(256):
            padding =



def test_the_attack():
    for msg in messages:
        print('Testing:', msg)
        cracked_ct = attack(encrypt(msg))
        assert cracked_ct == msg


if __name__ == "__main__":
    main()
