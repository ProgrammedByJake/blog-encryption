from aes_helper import AESHelper


class AESState:
    def __init__(self, byte_array, key):
        assert type(byte_array) == bytes and len(byte_array) == 16, 'An AES State must be a byte array of length 16'
        self.array = [[byte_array[c * 4 + r] for c in range(4)] for r in range(4)]
        self.key = key

    def __str__(self):
        return ''.join([''.join([chr(self.array[r][c]) for r in range(4)]) for c in range(4)])

    def to_hex(self):
        return ''.join([''.join([f'{self.array[r][c]:02x}' for r in range(4)]) for c in range(4)])

    def to_byte_array(self):
        array = []
        for c in range(4):
            array += [self.array[r][c] for r in range(4)]
        return array

    # 5.1.1 - SubBytes() Transformation
    def SubBytes(self):
        self.array = [[AESHelper.S_BOX[self.array[r][c]] for c in range(4)] for r in range(4)]

    # 5.1.2 - ShiftRows() Transformation
    def ShiftRows(self):
        self.array = [[self.array[r][(c + r) % self.key.Nb] for c in range(self.key.Nb)] for r in range(self.key.Nb)]

    # 5.1.3 - MixColumns() Transformation
    def MixColumns(self):
        # This transformation is meant to be done column-wise.
        # To allow the use of list comprehension we produce a row-wise version of the formula and then flip the array.
        s = [[
                AESHelper.mult(0x02, self.array[r][c]) ^
                AESHelper.mult(0x03, self.array[(r + 1) % 4][c]) ^
                self.array[(r + 2) % 4][c] ^
                self.array[(r + 3) % 4][c]
            for r in range(4)] for c in range(4)]
        self.array = [[s[r][c] for r in range(4)] for c in range(4)]

    # 5.1.4 - AddRoundKey() Transformation
    def AddRoundKey(self, round):
        self.array = [[self.array[r][c] ^ self.key.array[round * 4 + c][r] for c in range(4)] for r in range(4)]
