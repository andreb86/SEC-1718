#!/usr/bin/env python3

import argparse

SPACE = ord(' ')


def main():
    parser = argparse.ArgumentParser(description="Many-time Pad Cracker")
    parser.add_argument("--filename", type=str,
                        help="Name of the file containing the ciphertexts (default: ciphertexts.txt)",
                        default="ciphertexts.txt")
    args = parser.parse_args()
    try:
        with open(args.filename) as f:

            # Open the file and read it into a list of bytes sequences
            ciphertexts = [bytearray.fromhex(line.rstrip()) for line in f]

        key_stream = bytearray(max(map(len, ciphertexts)))

    except Exception as e:
        print("Cannot crack {} --- {}".format(args.filename, e))
        raise SystemExit(-1)
    for k in range(max(len(c) for c in ciphertexts)):
        chars = [c[k] for c in ciphertexts if len(c) > k]
        max_no_spaces = 0
        index = 0
        for i, c1 in enumerate(chars):
            space_counter = 0
            for c2 in chars:
                if c1 ^ c2 > 65:
                    space_counter += 1
            if space_counter > max_no_spaces:
                max_no_spaces = space_counter
                index = i
        key_stream[k] = chars[index] ^ SPACE
    cleartexts = [xor(key_stream, c) for c in ciphertexts]
    print("\n".join(c.decode('ascii') for c in cleartexts))


def xor(a: bytes, b: bytes):

    """
    Return the byte sequence of the xor of two strings

    :param a:       First byte sequence
    :param b:       Second byte sequence
    :return:        The XOR of a and b
    """

    return bytes(x ^ y for x, y in zip(a, b))


if __name__ == "__main__":
    main()
