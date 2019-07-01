from aes_helper import AESHelper


class AESKey:
    def __init__(self, byte_array):
        assert type(byte_array) == bytes and len(byte_array) in [16, 24, 32], 'An AES Key must contain 128, 192 or 256 bits'

        # As defined in 5- Algorithm Specification
        Kl = len(byte_array)
        self.Nk = Kl // 4
        self.Nb = 4
        self.Nr = self.Nk + 6

        array = [byte_array[i*4:(i + 1) * 4] for i in range(self.Nk)]

        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = array[i - 1]
            if i % self.Nk == 0:
                temp = self.poly_addition(self.SubWord(self.RotWord(temp)), self.Rcon(i // self.Nk))
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self.SubWord(temp)
            word = self.poly_addition(array[i - self.Nk], temp)

            array.append(word)
            i += 1

        self.array = array

    @staticmethod
    def SubWord(word):
        return [AESHelper.S_BOX[b] for b in word]

    @staticmethod
    def RotWord(word):
        l = len(word)
        return [word[(i + 1) % l] for i in range(l)]

    @staticmethod
    def Rcon(i):
        return [1 << i - 1, 0, 0, 0]

    # 4.3 Polynomials with Coefficients in GF(2^8)
    @staticmethod
    def poly_addition(a, b):
        assert len(a) == 4 and len(b) == 4, "For polynomial addition, both elements need to be words of 4 bytes"
        return [AESHelper.modular_reduction(a[i] ^ b[i]) for i in range(4)]

    @staticmethod
    def poly_mult(a, b):
        assert len(a) == 4 and len(b) == 4, "For polynomial addition, both elements need to be words of 4 bytes"
        return [
            AESHelper.mult(a[0], b[0]) ^ AESHelper.mult(a[3], b[1]) ^ AESHelper.mult(a[2], b[2]) ^ AESHelper.mult(a[1], b[3]),
            AESHelper.mult(a[1], b[0]) ^ AESHelper.mult(a[0], b[1]) ^ AESHelper.mult(a[3], b[2]) ^ AESHelper.mult(a[2], b[3]),
            AESHelper.mult(a[2], b[0]) ^ AESHelper.mult(a[1], b[1]) ^ AESHelper.mult(a[0], b[2]) ^ AESHelper.mult(a[3], b[3]),
            AESHelper.mult(a[3], b[0]) ^ AESHelper.mult(a[2], b[1]) ^ AESHelper.mult(a[1], b[2]) ^ AESHelper.mult(a[0], b[3]),
        ]
