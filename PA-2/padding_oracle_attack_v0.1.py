from Crypto import Random
from functools import reduce
from oracle import encrypt, is_padding_ok, BLOCK_SIZE

messages = (b'Attack at dawn',
            b'',
            b'Giovanni',
            b"In symmetric cryptography, the padding oracle attack can be" +
            b"applied to the CBC mode of operation, where the \"oracle\" " +
            b"(usually a server) leaks data about whether the padding of " +
            b"an encrypted message is correct or not. Such data can allow" +
            b" attackers to decrypt (and sometimes encrypt) messages " +
            b"through the oracle using the oracle's key, without knowing " +
            b"the encryption key")

b = BLOCK_SIZE


def _split_blocks(ct: bytes) -> list:
    """
    Split the ciphertext into its blocks.
    
    :param ct:              ciphertext
    :return blocks:         list containing the blocks of the ciphertext
    """
    if len(ct) % b:
        print("Provided CipherText has wrong length.\nAborting.")
        raise IndexError
    else:
        blocks = [ct[i: i + b] for i in range(0, len(ct), b) if len(ct) > 0]
        if len(blocks) == 1:
            print("Empty CipherText.\nAborting")
            raise ValueError
        else:
            return blocks


def _build_challenge_ct(r: bytearray, y: bytes, j: int, i: int) -> bytes:
    """
    This function builds the chosen ciphertext for the oracle challenge.

    :param r:               random base block
    :param y:               block to be decrypted
    :param j:               index iterating from end to begin of block
    :param i:               guess
    :return c:              challenge ciphertext
    """
    r[j] = i
    c = bytes(r) + y
    return c


def _block_decryption_oracle(block: bytes) -> bytes:
    """
    This function iterates through each byte of the random block and changes
    its value to find the state of the message before decryption DEC(k, block).
    
    :param block:           block to be decrypted
    :return blk_state:      the AES decryption of the block before XOR'ing
    """
    
    rnd_block = bytearray(Random.new().read(b))
    blk_state = bytearray(b)
    for k in reversed(range(b)):
        for guess in range(256):
            chs_block = _build_challenge_ct(rnd_block, block, k, guess)
            if is_padding_ok(chs_block):
                blk_state[k] = chs_block[k] ^ (b - k)
                for l in range(k, b):
                    rnd_block[l] = blk_state[l] ^ (b - k + 1)
                break
    return blk_state


def _xor(*args) -> bytes:
    """
    Return the xor of at least two byte strings. The output length equals
    the length of the shortest string.
    
    :type args:             bytes
    :param args:            a variable number of bytes string
    :return xored:          the XOR of the strings provided
    """
    
    if len(args) < 2:
        raise SyntaxError
    return bytes(reduce(lambda x, y: x ^ y, t) for t in zip(*args))
    
    

def attack(ciphertext: bytes) -> bytes:
    """
    
    :param ciphertext:      the encrypted messae
    :return cleartext:      the decrypted message
    """
    blocks = _split_blocks(ciphertext)
    message_state = b''.join(
        [_block_decryption_oracle(b1) for b1 in blocks[1:]]
    )
    ct1 = ciphertext[:-b]
    cleartext = _xor(ct1, message_state)
    pad = cleartext[-1]
    return cleartext[:-pad]


def main():
    try:
        for msg in messages:
            print("Testing:", msg.decode('ASCII'))
            ct = encrypt(msg)
            decrypted = attack(ct)
            print('Decrypted message:', decrypted.decode('ASCII'))
            assert attack(ct) == msg
    except AssertionError as ae:
        print("Attack Failed", str(ae))
    except SyntaxError as se:
        print("Improper use of the xor function.")


if __name__ == "__main__":
    main()
