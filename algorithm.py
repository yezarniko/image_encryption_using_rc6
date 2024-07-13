"""
Algorithm:

 - Key generation:
    S [0] = P32
    for i = 1 to 2r + 3 do
    {
        S [i] = S [i - 1] + Q32
    }
    A = B = i = j = 0
    v = 3 X max{c, 2r + 4}
    for s = 1 to v do
    {
        A = S [i] = (S [i] + A + B) <<< 3
        B = L [j] = (L [j] + A + B) <<< (A + B)
        i = (i + 1) mod (2r + 4)
        j = (j + 1) mod c
    }

 - Encryption:
    B = B + S[0]
    D = D + S[1]
    for i = 1 to r do
    {
        t = (B * (2B + 1)) <<< lg w
        u = (D * (2D + 1)) <<< lg w
        A = ((A ^ t) <<< u) + S[2i]
        C = ((C ^ u) <<< t) + S[2i + 1] 
        (A, B, C, D)  =  (B, C, D, A)
    }
    A = A + S[2r + 2]
    C = C + S[2r + 3]

 - Decryption:
    C = C - S[2r + 3]
    A = A - S[2r + 2]

    for i = r downto 1 do
    {
        (A, B, C, D) = (D, A, B, C)
        u = (D * (2D + 1)) <<< lg w
        t = (B * (2B + 1)) <<< lg w
        C = ((C - S[2i + 1]) >>> t) ^ u
        A = ((A - S[2i]) >>> u) ^ t
    }
    D = D - S[1]
    B = B - S[0]
"""

from typing import Tuple, List, Union
from functools import partial

basetwo = partial(int, base=2)
unblock = partial(int.to_bytes, length=4, byteorder="little")


class RC6Encryption:

    """
    This class implements the RC6 encryption.

    Rounds possible values: {12, 16, 20}
    """

    P32 = 0xB7E15163 # Odd((e-2)2^32)
    Q32 = 0x9E3779B9 # Odd((θ-2)2^32)

    def __init__(
        self, key: bytes, rounds: int = 20, w_bit: int = 32, lgw: int = 5
    ):
        self.key_bytes = key
        self.rounds = rounds
        self.w_bit = w_bit
        self.lgw = lgw

        self.round2_2 = rounds * 2 + 2 # 42
        self.round2_3 = self.round2_2 + 1 # 43 
        self.round2_4 = self.round2_3 + 1 # 44

        self.modulo = 2**w_bit # 2^32

        (
            self.key_binary_blocks,
            self.key_integer_reverse_blocks,
        ) = self.get_blocks(key)
        self.key_blocks_number = len(self.key_binary_blocks)

        self.rc6_key = [self.P32] # init with p32

        # self.key_generation()

    @staticmethod
    def get_blocks(data: bytes) -> Tuple[List[str], List[int]]:
        """
        This function returns blocks (binary strings and integers) from data.
        """

        binary_blocks = []
        integer_blocks = []
        block = ""

        for i, char in enumerate(data):
            if i and not i % 4:
                binary_blocks.append(block)
                integer_blocks.append(basetwo(block))
                block = ""
            block = f"{char:0>8b}{block}"

        binary_blocks.append(block)
        integer_blocks.append(basetwo(block))

        return binary_blocks, integer_blocks

    @staticmethod
    def blocks_to_data(blocks: List[int]) -> bytes:
        """
        This function returns data from blocks (binary strings).
        """

        data = b""

        for block in blocks:
            data += unblock(block)

        return data

    def right_rotation(self, x: int, n: int) -> int:
        """
        This function perform a right rotation.
        """

        mask = (2**n) - 1
        mask_bits = x & mask
        return (x >> n) | (mask_bits << (self.w_bit - n))

    def left_rotation(self, x: int, n: int) -> int:
        """
        This function perform a left rotation (based on right rotation).
        """

        return self.right_rotation(x, self.w_bit - n)

    def key_generation(self) -> List[int]:
        """
        This function generate the key.
        """

        for i in range(0, self.round2_3):
            self.rc6_key.append((self.rc6_key[i] + self.Q32) % self.modulo)
        

        a = b = i = j = 0
        v = 3 * (
            self.key_blocks_number
            if self.key_blocks_number > self.round2_4
            else self.round2_4
        )

        for i_ in range(v):
            a = self.rc6_key[i] = self.left_rotation(
                (self.rc6_key[i] + a + b) % self.modulo, 3
            )
            b = self.key_integer_reverse_blocks[j] = self.left_rotation(
                (self.key_integer_reverse_blocks[j] + a + b) % self.modulo,
                (a + b) % 32,
            )
            i = (i + 1) % (self.round2_4)
            j = (j + 1) % self.key_blocks_number

        return self.rc6_key
    
    def encrypt(
        self, data: Union[bytes, Tuple[int, int, int, int]]
    ) -> List[int]:
        """
        This functions performs RC6 encryption on only one block.

        This function returns a list of 4 integers.
        """

        if isinstance(data, bytes):
            _, data = self.get_blocks(data)
        a, b, c, d = data

        b = (b + self.rc6_key[0]) % self.modulo
        d = (d + self.rc6_key[1]) % self.modulo

        for i in range(1, self.rounds + 1):
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            a = (
                self.left_rotation(a ^ t, umod) + self.rc6_key[2 * i]
            ) % self.modulo
            c = (
                self.left_rotation(c ^ u, tmod) + self.rc6_key[2 * i + 1]
            ) % self.modulo
            a, b, c, d = b, c, d, a

        a = (a + self.rc6_key[self.round2_2]) % self.modulo
        c = (c + self.rc6_key[self.round2_3]) % self.modulo

        return [a, b, c, d]

    def decrypt(self, data: bytes) -> List[int]:
        """
        This function performs a RC6 decryption.
        """

        if isinstance(data, bytes):
            _, data = self.get_blocks(data)
        a, b, c, d = data

        c = (c - self.rc6_key[self.round2_3]) % self.modulo
        a = (a - self.rc6_key[self.round2_2]) % self.modulo

        for i in range(self.rounds, 0, -1):
            (a, b, c, d) = (d, a, b, c)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            c = (
                self.right_rotation(
                    (c - self.rc6_key[2 * i + 1]) % self.modulo, tmod
                )
                ^ u
            )
            a = (
                self.right_rotation(
                    (a - self.rc6_key[2 * i]) % self.modulo, umod
                )
                ^ t
            )

        d = (d - self.rc6_key[1]) % self.modulo
        b = (b - self.rc6_key[0]) % self.modulo

        return [a, b, c, d]
