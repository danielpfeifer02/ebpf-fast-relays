# This file is to get an idea of how the decryption of the chacha20poly1305 algorithm works.
# Once the process is understood the goal is to implement the decryption in ebpf via the "hand down"
# of the necessary bitstream for deciphering the encrypted data.

nonceraw = """ 

"""
nonce = bytes.fromhex(nonceraw.strip().replace(" ", ""))

cipherraw = """

"""
ciphertext = bytes.fromhex(cipherraw.strip().replace(" ", ""))

additionaldataraw = """ 

"""
additionaldata = bytes.fromhex(additionaldataraw.strip().replace(" ", ""))

keyraw = """

"""
key = bytes.fromhex(keyraw.strip().replace(" ", ""))


tag = ciphertext[-16:]
ciphertext = ciphertext[:-16]


streamcipherbuffer = []
blocksize = 64
counter = 0
j0 = 0x61707865 # expa
j1 = 0x3320646e # nd 3
j2 = 0x79622d32 # 2-by
j3 = 0x6b206574 # te k

# ...NewUnauthenticatedCipher(...) only reads in the key and the nonce into a new cipher object
# nothing to do

# ...XORKeyStream(...) 
# TODO

# ...SetCounter(1)
# TODO

# ...poly1305.New(...)
# TODO

# ...write...(poly1305.MAC, ...)
# TODO

# ...sliceForAppend...)
# TODO

# ...XORKeyStream(...)
# TODO



def xorkeystream():
    # TODO: add support for multiple rounds where the stream buffer might still be filled
    numblocks = (len(ciphertext) + blocksize - 1) // blocksize


    full = len(ciphertext) - (len(ciphertext) % blocksize)

def xorkeystreamblocksgeneric():
    c0, c1, c2, c3 = j0, j1, j2, j3
    c4, c5, c6, c7 = key[0], key[1], key[2], key[3]
    c8, c9, c10, c11 = key[4], key[5], key[6], key[7]
    _, c13, c14, c15 = counter, nonce[0], nonce[1], nonce[2]
    
    p1, p5, p9, p13 = quarterround(c1, c5, c9, c13)
    p2, p6, p10, p14 = quarterround(c2, c6, c10, c14)
    p3, p7, p11, p15 = quarterround(c3, c7, c11, c15)

    while len(ciphertext) >= 64:
        fcr0, fcr4, fcr8, fcr12 = quarterround(c0, c4, c8, counter)

        x0, x5, x10, x15 = quarterround(fcr0, p5, p10, p15)
        ...


def quarterround(a, b, c, d):
    a = (a + b) & 0xffffffff
    d ^= a
    d = (d << 16 | d >> 16) & 0xffffffff
    c = (c + d) & 0xffffffff
    b ^= c
    b = (b << 12 | b >> 20) & 0xffffffff
    a = (a + b) & 0xffffffff
    d ^= a
    d = (d << 8 | d >> 24) & 0xffffffff
    c = (c + d) & 0xffffffff
    b ^= c
    b = (b << 7 | b >> 25) & 0xffffffff
    return a, b, c, d

def addxor(dst_index, src_index, a, b):
    a = (a + b) & 0xffffffff
    