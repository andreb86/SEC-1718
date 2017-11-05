from Crypto import Random
from oracle import encrypt, is_padding_ok
from oracle import BLOCK_SIZE as b

messages = (b'Attack at dawn', b'', b'Giovanni',
            b"In symmetric cryptography, the padding oracle attack can be applied to the CBC mode of operation," +
            b"where the \"oracle\" (usually a server) leaks data about whether the padding of an encrypted " +
            b"message is correct or not. Such data can allow attackers to decrypt (and sometimes encrypt) " +
            b"messages through the oracle using the oracle's key, without knowing the encryption key")


def _split_blocks(ct: bytes):
    if len(ct) % b:
        print("Provided CipherText has wrong length.\nAborting.")
        raise IndexError
    else:
        blocks = [ct[i: i + b] for i in range(0, len(ct), b) if len(ct) > 0]
        if len(blocks) == 1:
            print("Empty CipherText.\nAborting")
            raise ValueError
        else:
            return reversed(blocks)


def _last_word_oracle(y: bytes) -> tuple:
    r = Random.new().read(b)
    d = bytearray(b)
    c = bytearray(r)
    for i in range(256):
        print(f'Guessing last byte of block: {i: d}')
        c[-1] = r[-1] ^ i
        if is_padding_ok(bytes(c) + y):
            d[-1] = c[-1] ^ 1
            break
    for n in range(b, 2, -1):
        c[b - n + 1] = r[b - n + 1] ^ 1
        if not is_padding_ok(bytes(c) + y):
            for k in
        

def _block_decryption_oracle(block: bytes) -> bytes:
    rnd_block = bytearray(b)
    dec_block = bytearray(b)
    for k in reversed(range(b)):
        for guess in range(256):
            chs_block = _build_challenge_ct(rnd_block, block, k, guess)
            if is_padding_ok(chs_block):
                dec_block[k] = guess
                for l in range(k, b):
                    rnd_block[l] = chs_block[l] ^ (b - k) ^ (b - k + 1)
            break
    return dec_block


def attack(ciphertext: bytes) -> bytes:
    blocks = _split_blocks(ciphertext)
    cleartext = []
    for block in blocks:
        cleartext.append(_block_decryption_oracle(block))
    print(cleartext)
    return cleartext


def test_the_attack():
    for msg in messages:
        print('Testing:', msg)
        cracked_ct = attack(encrypt(msg))
        assert cracked_ct == msg


def main():
    try:
        assert attack(encrypt(b'Andrea')) == b'Andrea'
    except AssertionError as e:
        print("Attack Failed", str(e))


if __name__ == "__main__":
    main()
