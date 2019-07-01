"""
My implementation of the AES algorithm, based on the NIST FIPS 197 found at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
"""
from aes_key import AESKey
from aes_state import AESState


class AES:

    @staticmethod
    def encrypt(message, key):
        # Allow key to be bytes or a string
        if type(key) == bytes:
            key_bytes = key
        elif type(key) == str:
            key_bytes = bytearray()
            key_bytes.extend(map(ord, key))
            while len(key_bytes) % 16:
                key_bytes.extend([0])
        else:
            raise TypeError("Key must be a byte array or string")

        aes_key = AESKey(key_bytes)

        # Allow message to be bytes or a string
        if type(message) == bytes:
            message_bytes = message
        elif type(message) == str:
            message_bytes = bytearray()
            message_bytes.extend(map(ord, message))
            while len(message_bytes) % 16:
                message_bytes.extend([0])
        else:
            raise TypeError("Message must be a byte array or string")

        output = ""
        for block_n in range(len(message_bytes) // 16):
            block = message_bytes[16 * block_n: 16 * block_n + 16]
            state = AESState(block, aes_key)

            state.AddRoundKey(0)
            for round in range(1, aes_key.Nr + 1):
                state.SubBytes()
                state.ShiftRows()
                if round != aes_key.Nr:
                    state.MixColumns()
                state.AddRoundKey(round)

            output += state.to_hex()
        return output

    @staticmethod
    def decrypt(message, key):
        # As defined in 3.1 - Input and Output, a key must be 128, 192 or 156 bits
        key_bytes = bytearray()
        key_bytes.extend(map(ord, key))
        if len(key_bytes) * 8 not in [128, 192, 256]:
            raise ValueError("Key must of of length 128, 192 or 256")

        return ""
