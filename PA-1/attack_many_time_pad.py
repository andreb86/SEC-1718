# /usr/bin/python

import binascii
import collections
import itertools
import os
import string
import re

# Define the separator of the messages.
double_caret = re.compile(b'\n\n')


def attack_mtp(ciphertext: str):
    """
    Attack the many time pad.
    
    :param ciphertext:  Input file
    :return:            Key
    """
    
    # Open the ciphertext file.
    try:
        with open(ciphertext, 'r') as f:
            
            # Split the file into a list.
            ct_list = [binascii.unhexlify(i.rstrip()) for i in f]
            
            # Return the list of ciphertexts XOR'd with each other.
            xored_ct = xor_permutations(ct_list)
            
            # Initialise the space counter.
            space_counter = [collections.Counter()] * len(ct_list)
            
            # Iterate through the list of xored CT's.
            for x in xored_ct[0:6]:
                
                # Store the space counter into a temporary variable.
                tmp_counter = space_count(x[2])

                # Increment the space counter for each CT.
                space_counter[x[0]].update(tmp_counter)
                space_counter[x[1]].update(tmp_counter)

                print(space_counter, sep='\n')
                print(tmp_counter)

                # Reset the temporary counter.
                tmp_counter.clear()
                
            # Return the partial key.
            return ct_list, xored_ct, space_counter
    
    # Handle exception.
    except FileNotFoundError as fnf_err:
        
        # Print error.
        print('CTs file not found: ', str(fnf_err))
        
        # Exit the function.
        return -1


def xor(a: bytes, b: bytes):
    """
    Return the xor of two bytes sequences.
    
    :param a:   First bytes sequence
    :param b:   Second bytes sequence
    :return:    The xor'd bytes sequence
    """
    
    return bytes(x ^ y for x, y in zip(a, b))


def xor_permutations(ct_list):
    """
    XOR all of the CT's in the list.
    
    :param ct_list: list of all of the CT's
    :return:        list with the XOR's of the CT's
    """
    
    return list(
        (
            c0[0],
            c1[0],
            xor(c0[1], c1[1])
        ) for c0, c1 in itertools.combinations(enumerate(ct_list), 2)
    )


def space_count(xored: bytes):
    """
    Return the indexes of the spaces in one string which is the xor of two
    CT's.
    
    :param xored:
    :return:
    """
    
    # Init the output list.
    spaces = collections.Counter()
    
    # Iterate through each byte of the xor'd CT's.
    for i, b in enumerate(xored):
        
        # Update the counter of the spaces.
        if b in [*range(65, 91), *range(97, 123)]:
            spaces[i] += 1
    
    return spaces
