import base64
from typing import Generator


class RC4Cipher:

    def __init__(self, key: str | None = None) -> None:
        self._key = key
        self._key_schedule = RC4Cipher._get_key_schedule(key)

    @property
    def key(self) -> str | None:
        return self._key

    @key.setter
    def key(self, key: str):
        self._key = key
        self._key_schedule = RC4Cipher._get_key_schedule(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt a plain text using RC4 and the provided key.
        :param plaintext: Text to encrypt.
        :return: Encrypted plaintext, base64 encoded.
        """

        if self._key_schedule is None:
            raise ValueError("Key is not set. Please import a key.")

        plaintext = plaintext.decode()
        plaintext = [ord(char) for char in plaintext]

        key_stream = self._key_stream_gen()

        ciphertext = list()
        for character in plaintext:
            # XOR each character from the plain text with an element from the key stream.
            ciphertext.append(chr(character ^ next(key_stream)))

        ciphertext = ''.join(ciphertext)

        return base64.b64encode(ciphertext.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt a ciphertext using RC4 and the provided key.
        :param ciphertext: Text to decrypt, base64 encoded.
        :return: Decrypted ciphertext.
        """
        ciphertext = base64.b64decode(ciphertext).decode()
        ciphertext = [ord(character) for character in ciphertext]

        key_stream = self._key_stream_gen()

        plaintext = list()
        for character in ciphertext:
            plaintext.append(bytes(chr(character ^ next(key_stream)), encoding='utf-8'))

        return b''.join(plaintext)

    @staticmethod
    def _get_key_schedule(key: str | None = None) -> list | None:
        """
        Key scheduling algorithm which is used to initialize the schedule list.
        :param key: Secret key.
        :return: Initialized key schedule.
        """
        if key is None:
            return None
        key = [ord(character) for character in key]
        # Initialize the schedule with the identity permutation.
        schedule = [i for i in range(0, 256)]

        i = 0
        for j in range(0, 256):
            # Process the schedule list for 256 iterations.
            i = (i + schedule[j] + key[j % len(key)]) % 256

            # Swap
            schedule[j], schedule[i] = schedule[i], schedule[j]
        return schedule

    def _key_stream_gen(self) -> Generator[int, None, None]:
        """
        Generator that implements the RC4 Pseudo-random generation algorithm (PRGA).
        :return: One byte of the key stream at a time.
        """
        # Make a copy of the key schedule. This is needed in order to avoid re-making the schedule every time
        # you need to encrypt/decrypt something with the same key.
        schedule = self._key_schedule.copy()
        i = 0
        j = 0

        while True:
            i = (1 + i) % 256
            j = (schedule[i] + j) % 256

            schedule[i], schedule[j] = schedule[j], schedule[i]

            yield schedule[(schedule[i] + schedule[j]) % 256]


if __name__ == '__main__':
    cipher = RC4Cipher('test')

