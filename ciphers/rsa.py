import os
from abc import ABC, abstractmethod
import base64

from Crypto.Util import number
from Crypto.Util.strxor import strxor
from Crypto.Util.asn1 import DerSequence
from Crypto.IO import PEM
import hashlib
import math
from random import randbytes


class RSAKey(ABC):

    @abstractmethod
    def import_key(self, key: str | bytes) -> None:
        pass

    @abstractmethod
    def export_key(self) -> str:
        pass

    def import_from_file(self, path: os.PathLike | str):
        with open(path, 'r') as f:
            key = f.read()
        self.import_key(key)

    def export_to_file(self, path: os.PathLike | str):
        key_pem = self.export_key()
        with open(path, 'w') as f:
            f.write(key_pem)


class RSAPublicKey(RSAKey):
    """
    Class to define the structure of an RSA Public Key.
    """
    modulus: int
    exponent: int

    def __init__(self, modulus: int | None = None, exponent: int | None = None):
        self.modulus = modulus
        self.exponent = exponent

    def encrypt_int(self, integer_message: int) -> int:
        """
        Encrypting a message using the public key, it raises the message converted to an integer to the public
        exponent then it gets the modulus using the modulus of the public key.
        :param integer_message: Message to encrypt, transformed into an integer
        :return: Encrypted message, as an integer
        """
        return int(pow(integer_message, self.exponent, self.modulus))

    def export_key(self) -> str:
        """
        Encodes the RSA public key to the ASN.1 DER format then transforms it into the well known PEM format.
        :return: PEM-encoded RSA public key.
        """
        key = DerSequence([self.modulus,
                           self.exponent]).encode()
        pem = PEM.encode(key, 'RSA PUBLIC KEY')
        return pem

    def import_key(self, key: str | bytes) -> None:
        der, key_type, _, = PEM.decode(key)
        if key_type != 'RSA PUBLIC KEY':
            raise ValueError('Trying to import a RSA Private Key in an RSAPublicKey object.')
        raw_key_data = DerSequence().decode(der, nr_elements=2, only_ints_expected=True)

        # Reinitialize the current object
        self.__init__(*raw_key_data)


class RSAPrivateKey(RSAKey):
    """
    Class to define the structure of an RSA Private Key
    """
    version: int = 0
    modulus: int  # n
    public_exponent: int  # e
    private_exponent: int  # d
    prime1: int  # p
    prime2: int  # q
    exponent1: int = None
    exponent2: int = None
    coefficient: int = None

    def __init__(self,
                 modulus: int | None = None,
                 public_exponent: int | None = None,
                 private_exponent: int | None = None,
                 prime1: int | None = None,
                 prime2: int | None = None):
        self.modulus = modulus  # n
        self.public_exponent = public_exponent  # e
        self.private_exponent = private_exponent  # d
        self.prime1 = prime1  # p
        self.prime2 = prime2  # q
        # The fields below are part of the RSA ASN.1 format and are normally used with the Chinese Remainder
        # Theorem to decrypt messages.
        if private_exponent is not None:
            self.exponent1 = private_exponent % (prime1 - 1)
            self.exponent2 = private_exponent % (prime2 - 1)
        if prime1 is not None:
            self.coefficient = int((prime1 ** -1) % prime1)

    def decrypt_int(self, cipher_text_int: int) -> int:
        """
        This method takes in an RSA-encrypted message (Integer format) and decrypts it by raising it to the power
        of the private exponent and then doing the modulus operation with the key's modulus.
        This method would ideally use the Chinese Remainder theorem to decrypt the message as it is a more
        secure method of doing so.
        :param cipher_text_int: Encrypted message as int.
        :return: Decrypted message as int.
        """
        # Improvement needed here.
        return int(pow(cipher_text_int, self.private_exponent, self.modulus))

    def get_public(self) -> RSAPublicKey:
        """
        Derives a public key from a private key.
        :return: Corresponding public key from a RSA private key.
        """
        if not self.modulus:
            raise ValueError("Modulus is not set.")
        if not self.public_exponent:
            raise ValueError("Public exponent is not set.")

        return RSAPublicKey(self.modulus, self.public_exponent)

    def export_key(self) -> str:
        """
        Encodes the RSA private key to the ASN.1 DER format then transforms it into the well known PEM format.
        :return: PEM-encoded RSA private key.
        """
        key = DerSequence([0,
                           self.modulus,
                           self.public_exponent,
                           self.private_exponent,
                           self.prime1,
                           self.prime2,
                           self.exponent1,
                           self.exponent2,
                           self.coefficient]).encode()
        pem = PEM.encode(key, 'RSA PRIVATE KEY')
        return pem

    def import_key(self, key: str | bytes) -> None:
        der, key_type, _, = PEM.decode(key)
        if key_type != 'RSA PRIVATE KEY':
            raise ValueError('Trying to import a RSA Public Key in an RSAPrivateKey object.')
        raw_key_data = DerSequence().decode(der, nr_elements=9, only_ints_expected=True)[:]

        # Reinitialize the current object
        self.__init__(*(raw_key_data[1:6]))


class RSACipher:
    public_key: RSAPublicKey
    private_key: RSAPrivateKey

    def __init__(self, private_key: RSAPrivateKey = None, public_key: RSAPublicKey = None):
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def gen_keypair(size: int) -> tuple[RSAPrivateKey, RSAPublicKey]:
        """
        This method generates an RSA keypair. It generates two random prime numbers and then computes all other
        required elements to create an RSA keypair.
        :param size: Size of the prime numbers used to generate the keypair, in bits. RSA key size will be double.
        :return: Tuple containing the private key and public key.
        """
        # Generates the two prime numbers, these should be kept secret and are part of the private key.
        p = number.getPrime(size)
        q = number.getPrime(size)

        # Calculate n, which is used as the modulus for the private and public key. Its size is 2 * size
        # And it is the actual size of the RSA keys.
        n = p * q

        # Euler's totient function
        totient = (p - 1) * (q - 1)

        # the public exponent e, it is usually chosen as (2^16) + 1
        e = 65537

        # We get the private exponent by raising the inverse of the public exponent to the power of the totient
        d = pow(e, -1, totient)

        # We now have all the components of the keys, so we create the objects and return them.
        pub_key = RSAPublicKey(n, e)
        private_key = RSAPrivateKey(n, e, d, p, q)

        return private_key, pub_key

    @staticmethod
    def _mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
        """
        Mask Generation Function 1. This is used for the OAEP padding when encrypting and decrypting messages.
        :return:
        """
        h_len = hash_func().digest_size
        # This implementation follows the RFC mentioned below.
        # https://www.ietf.org/rfc/rfc2437.txt
        # 1.If l > 2^32(hLen), output "mask too long" and stop.
        if length > (h_len << 32):
            raise ValueError("mask too long")
        # 2.Let T  be the empty octet string.
        t = b""
        # 3.For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
        counter = 0
        while len(t) < length:
            # a.Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
            c = int.to_bytes(counter, 4, 'big')
            # b.Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
            t += hash_func(seed + c).digest()
            counter += 1
        # 4.Output the leading l octets of T as the octet string mask.
        return t[:length]

    def encrypt(self, message: bytes) -> bytes:
        """
        Function to encrypt a message using the RSA Public key. This function first applies OAEP padding to the
        message then encrypts it.
        :param message: Message to encrypt in bytes format.
        :return: Encrypted bytes.
        """
        if self.public_key is None:
            raise ValueError("Public key is not set.")

        # This implementation follows https://www.ietf.org/rfc/rfc2437.txt
        h = hashlib.sha256()
        h_len = h.digest_size
        h.update(''.encode())
        m_len = len(message)

        modulus_size_bits = self.public_key.modulus.bit_length()
        k = math.ceil(modulus_size_bits / 8.0)

        # Step 1b
        ps_len = k - m_len - 2 * h_len - 2
        if ps_len < 0:
            raise ValueError("Input message too long for cipher size.")

        # Step 2a
        l_hash = h.digest()

        # Step 2b
        ps = b'\x00' * ps_len

        # Step 2c
        db = l_hash + ps + b'\x01' + message

        # Step 2d
        random_octet_seed = randbytes(h_len)

        # Step 2e
        db_mask = RSACipher._mgf1(random_octet_seed, k - h_len - 1)

        # Step 2f
        masked_db = strxor(db, db_mask)

        # Step 2g
        seed_mask = RSACipher._mgf1(masked_db, h_len)

        # Step 2h
        masked_seed = strxor(random_octet_seed, seed_mask)

        # Step 2i
        encoded_message = b'\x00' + masked_seed + masked_db

        encoded_message_int = int.from_bytes(encoded_message, 'big')
        encrypted_message_int = self.public_key.encrypt_int(encoded_message_int)
        encrypted_message = encrypted_message_int.to_bytes(k, 'big')
        return base64.b64encode(encrypted_message)

    def decrypt(self, cipher_text: bytes) -> str:
        """
        Decrypts an RSA OAEP padded message using the private key.
        :param cipher_text: Encrypted bytes, base64 encoded.
        :return: Decrypted ciphertext
        """
        if self.private_key is None:
            raise ValueError("Public key is not set.")

        cipher_text = base64.b64decode(cipher_text)

        # This implementation follows this RFC for the decryption: https://www.ietf.org/rfc/rfc2437.txt
        modulus_size_bits = self.private_key.modulus.bit_length()
        k = math.ceil(modulus_size_bits / 8.0)
        h = hashlib.sha256()
        h_len = h.digest_size

        # Step 2a (O2SIP)
        cipher_text_int = int.from_bytes(cipher_text, 'big')
        # Step 2b (RSADP)
        message_int = self.private_key.decrypt_int(cipher_text_int)
        # Complete step 2c (I2OSP)
        encoded_message = message_int.to_bytes(k, 'big')

        # Step 3a
        h.update(''.encode())
        l_hash = h.digest()

        # Step 3b, Y should be 0 here.
        y = encoded_message[0]
        masked_seed = encoded_message[1:h_len + 1]

        masked_db = encoded_message[h_len + 1:]

        # Step 3c
        seed_mask = RSACipher._mgf1(masked_db, h_len)
        # Step 3d
        seed = strxor(masked_seed, seed_mask)
        # Step 3e
        db_mask = RSACipher._mgf1(seed, k - h_len - 1)
        # Step 3f
        data_block = strxor(masked_db, db_mask)
        # Step 3g

        one_pos = h_len + data_block[h_len:].find(b'\x01')
        l_hash1 = data_block[:h_len]
        invalid = y | int(one_pos < h_len)
        hash_compare = strxor(l_hash1, l_hash)
        for x in hash_compare:
            invalid |= x
        for x in data_block[h_len:one_pos]:
            invalid |= x
        if invalid != 0:
            raise ValueError("Incorrect decryption")
        # Step 4
        return data_block[one_pos + 1:].decode()


if __name__ == '__main__':
    pass
