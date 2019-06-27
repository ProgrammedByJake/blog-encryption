"""
My implementation of the MD5 algorithm, based on the RFC 1321 found at https://tools.ietf.org/html/rfc1321
"""
from math import floor, sin
import struct


class MD5:
    @staticmethod
    def hash(message):
        # Step 1 - Append Padding Bits
        message_bytes = bytearray()
        message_bytes.extend(map(ord, message + chr(128)))
        while len(message_bytes) % 64 != 56:
            message_bytes.extend([0])

        # Step 2 - Append Length
        message_bytes.extend((len(message) * 8 % pow(2, 64)).to_bytes(8, 'little'))
        M = [sum([message_bytes[i + n] * pow(2, n * 8) for n in range(4)]) for i in range(0, len(message_bytes), 4)]  # Convert to words

        # Step 3 - Initialize the MD Buffer
        A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

        # Step 4 - Process Message in 16-Word Blocks
        F = lambda X, Y, Z: (X & Y) | (~X & Z)
        G = lambda X, Y, Z: (X & Z) | (Y & ~Z)
        H = lambda X, Y, Z: X ^ Y ^ Z
        I = lambda X, Y, Z: Y ^ (X | ~Z)

        T = [floor(4294967296 * abs(sin(i + 1))) for i in range(64)]

        rot = lambda x, n: (x << n) | (x >> (32 - n))
        add = lambda x, y: (x + y) % pow(2, 32)

        for block_index in range(len(M) // 16):
            X = M[block_index * 16:(block_index + 1) * 16]
            AA, BB, CC, DD = A, B, C, D
            R = lambda k, s, i, x: add(B,rot(add(add(add(A, x), X[k]), T[i]), s))

            # Round 1
            for n in range(16):
                k = n
                s = [7, 12, 17, 22][n % 4]
                i = n
                x = F(B, C, D)
                A, B, C, D = D, R(k, s, i, x), B, C

            # Round 2
            for n in range(16):
                k = (1 + 5 * n) % 16
                s = [5, 9, 14, 20][n % 4]
                i = n + 16
                x = G(B, C, D)
                A, B, C, D = D, R(k, s, i, x), B, C

            # Round 3
            for n in range(16):
                k = (5 + 3 * n) % 16
                s = [4, 11, 16, 23][n % 4]
                i = n + 32
                x = H(B, C, D)
                A, B, C, D = D, R(k, s, i, x), B, C

            # Round 4
            for n in range(16):
                k = (7 * n) % 16
                s = [6, 10, 15, 21][n % 4]
                i = n + 48
                x = I(B, C, D)
                A, B, C, D = D, R(k, s, i, x), B, C

            A, B, C, D = add(A, AA), add(B, BB), add(C, CC), add(D, DD)

        # Step 5 - Output
        change_endian = lambda x: struct.unpack("<I", struct.pack(">I", x))[0]
        return f'{change_endian(A):08x}{change_endian(B):08x}{change_endian(C):08x}{change_endian(D):08x}'
