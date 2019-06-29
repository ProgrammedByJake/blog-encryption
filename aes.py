"""
My implementation of the AES algorithm, based on the NIST FIPS 197 found at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
"""


class AES:
    # Substitution Table as Shown in 5.1.1 - SubBytes() Transformation
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ]

    @staticmethod
    def encrypt(message, key):
        # 5.1.1 - SubBytes() Transformation
        def SubBytes(s):
            return [[AES.S_BOX[s[r][c]] for c in range(4)] for r in range(4)]

        # 5.1.2 - ShiftRows() Transformation
        def ShiftRows(s):
            return [[s[r][(c + r) % Nb] for c in range(4)] for r in range(4)]

        # 5.1.3 - MixColumns() Transformation
        def MixColumns(s):
            # This transformation is meant to be done column-wise.
            # To allow the use of list comprehension we product a row-wise version of the formula and then flip the array.
            s = [[AES.mult(0x02, s[r][c]) ^ AES.mult(0x03, s[(r + 1) % 4][c]) ^ s[(r + 2) % 4][c] ^ s[(r + 3) % 4][c] for r in range(4)] for c in range(4)]
            return [[s[r][c] for r in range(4)] for c in range(4)]

        # 5.1.4 - AddRoundKey() Transformation
        def AddRoundKey(s, w):
            return [[s[r][c] ^ w[c] for c in range(4)] for r in range(4)]

        def KeyExpansion(key):
            def SubWord(word):
                return [AES.S_BOX[b] for b in word]

            def RotWord(word):
                l = len(word)
                return [word[(i + 1) % l] for i in range(l)]

            def Rcon(i):
                return [1 << i - 1, 0, 0, 0]

            w = [key[i*4:(i + 1) * 4] for i in range(4)]

            i = Nk
            while i < Nb * (Nr + 1):
                temp = w[i - 1]
                if i % Nk == 0:
                    temp = AES.poly_addition(SubWord(RotWord(temp)), Rcon(i//Nk))
                elif Nk > 6 and i % Nk == 4:
                    temp = SubWord(temp)
                w.append(AES.poly_addition(w[i - Nk], temp))
                i += 1

            return w

        K = bytearray()
        K.extend(map(ord, key))
        Kl = len(K)

        # As defined in 3.1 - Input and Output, a key must be 128, 192 or 156 bits
        if Kl * 8 not in [128, 192, 256]:
            raise ValueError("Key must of of length 128, 192 or 256")

        # As defined in 5- Algorithm Specification
        Nk = Kl // 4
        Nb = 4
        Nr = Nk + 6

        w = KeyExpansion(K)

        message_bytes = bytearray()
        message_bytes.extend(map(ord, message))
        while len(message_bytes) % 16:
            message_bytes.extend([0])

        output = ""
        for block_n in range(len(message_bytes) // 16):
            block = message_bytes[16 * block_n: 16 * block_n + 16]
            state = [[block[n * 4 + m] for m in range(4)] for n in range(4)]

            state = AddRoundKey(state, w[0: Nb])
            for round in range(1, Nr + 1):
                state = SubBytes(state)
                state = ShiftRows(state)
                if round != Nr:
                    state = MixColumns(state)
                state = AddRoundKey(state, w[round * Nb: (round + 1) * Nb])

            for r in range(4):
                for c in range(4):
                    output += chr(state[r][c])

        return output

    @staticmethod
    def decrypt(message, key):
        # As defined in 3.1 - Input and Output, a key must be 128, 192 or 156 bits
        key_bytes = bytearray()
        key_bytes.extend(map(ord, key))
        if len(key_bytes) * 8 not in [128, 192, 256]:
            raise ValueError("Key must of of length 128, 192 or 256")

        return ""

    @staticmethod
    def modular_reduction(x):
        # IMP: Change this to a log calculation
        bin_digits = len(f"{x:b}")
        for i in range(bin_digits - 8):
            if (x >> bin_digits - 1 - i) % 2:
                x = x ^ (0x11b << (bin_digits - 9 - i))
        return x

    # 4.2 Multiplication
    @staticmethod
    def mult(x, y):
        out = 0
        for i in range(8):
            if (x >> i) % 2:
                for j in range(8):
                    if (y >> j) % 2:
                        out = out ^ pow(2, i + j)

        return AES.modular_reduction(out)

    # 4.2.1 - Multiplication by x
    @staticmethod
    def xtime(x, n):
        if n == 0:
            return x
        x = x << 1

        x = AES.modular_reduction(x)
        return AES.xtime(x, n - 1)

    # 4.3 Polynomials with Coefficients in GF(2^8)
    @staticmethod
    def poly_addition(a, b):
        assert len(a) == 4 and len(b) == 4, "For polynomial addition, both elements need to be words of 4 bytes"
        return [a[i] ^ b[i] for i in range(4)]

    @staticmethod
    def poly_mult(a, b):
        assert len(a) == 4 and len(b) == 4, "For polynomial addition, both elements need to be words of 4 bytes"
        return [
            AES.mult(a[0], b[0]) ^ AES.mult(a[3], b[1]) ^ AES.mult(a[2], b[2]) ^ AES.mult(a[1], b[3]),
            AES.mult(a[1], b[0]) ^ AES.mult(a[0], b[1]) ^ AES.mult(a[3], b[2]) ^ AES.mult(a[2], b[3]),
            AES.mult(a[2], b[0]) ^ AES.mult(a[1], b[1]) ^ AES.mult(a[0], b[2]) ^ AES.mult(a[3], b[3]),
            AES.mult(a[3], b[0]) ^ AES.mult(a[2], b[1]) ^ AES.mult(a[1], b[2]) ^ AES.mult(a[0], b[3]),
        ]
