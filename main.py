import argparse

from ciphers.rsa import RSACipher, RSAPublicKey, RSAPrivateKey
from ciphers.rc4 import RC4Cipher
from ciphers.blowfish import BlowfishCipher


def encrypt_rsa(key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
    Encryption with the RSA algorithm.
    :param key: RSA Public key, in PEM, PKCS1. Will only be used if key_file is None.
    :param key_file: File containing the public key.
    :param in_file: File containing the input to encrypt.
    :param out_file: File where the encrypted output will be written.
    :return: None
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    rsa_key = RSAPublicKey()
    if key_file is not None:
        rsa_key.import_from_file(key_file)
    else:
        rsa_key.import_key(key)
    cipher = RSACipher(public_key=rsa_key)
    cipher_output = cipher.encrypt(cipher_input)

    if out_file is None:
        print(cipher_output.decode())
        return

    with open(out_file, 'wb') as f:
        f.write(cipher_output)


def decrypt_rsa(key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
    Decryption with the RSA algorithm.
    :param key: RSA Public key, in PEM, PKCS1. Will only be used if key_file is None.
    :param key_file: File containing the public key.
    :param in_file: File containing the input to encrypt.
    :param out_file: File where the encrypted output will be written.
    :return: None
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    rsa_key = RSAPrivateKey()
    if key_file is not None:
        rsa_key.import_from_file(key_file)
    else:
        rsa_key.import_key(key)
    cipher = RSACipher(private_key=rsa_key)
    cipher_output = cipher.decrypt(cipher_input)

    if out_file is None:
        print(cipher_output)
        return

    with open(out_file, 'w') as f:
        f.write(cipher_output)


def encrypt_symmetric(cipher: BlowfishCipher | RC4Cipher, key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
    Encrypts using one of the two symmetric key algorithms.
    :param cipher: Cipher instance to use, BlowfishCipher or RC4Cipher
    :param key: RSA Public key, in PEM, PKCS1. Will only be used if key_file is None.
    :param key_file: File containing the public key.
    :param in_file: File containing the input to encrypt.
    :param out_file: File where the encrypted output will be written.
    :return: None
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    if key_file is not None:
        with open(key_file, 'r') as f:
            key = f.read()

    cipher.key = key
    cipher_output = cipher.encrypt(cipher_input)
    if out_file is None:
        print(cipher_output)
        return

    with open(out_file, 'wb') as f:
        f.write(cipher_output)


def decrypt_symmetric(cipher: BlowfishCipher | RC4Cipher, key: str, key_file: str, in_file: str, out_file: str) -> None:
    """
    Decrypts using one of the two symmetric key algorithms.
    :param cipher: Cipher instance to use, BlowfishCipher or RC4Cipher
    :param key: RSA Public key, in PEM, PKCS1. Will only be used if key_file is None.
    :param key_file: File containing the public key.
    :param in_file: File containing the input to encrypt.
    :param out_file: File where the encrypted output will be written.
    :return: None
    """
    with open(in_file, 'rb') as f:
        cipher_input = f.read()

    if key_file is not None:
        with open(key_file, 'r') as f:
            key = f.read()

    cipher.key = key
    cipher_output = cipher.decrypt(cipher_input)

    if out_file is None:
        print(cipher_output.decode())
        return

    with open(out_file, 'wb') as f:
        f.write(cipher_output)


def encrypt(cipher: str, key: str, key_file: str, in_file: str, out_file: str):
    match cipher:
        case 'rsa':
            encrypt_rsa(key, key_file, in_file, out_file)
        case 'blowfish':
            encrypt_symmetric(BlowfishCipher(), key, key_file, in_file, out_file)
        case 'rc4':
            encrypt_symmetric(RC4Cipher(), key, key_file, in_file, out_file)


def decrypt(cipher: str, key: str, key_file: str, in_file: str, out_file: str):
    match cipher:
        case 'rsa':
            decrypt_rsa(key, key_file, in_file, out_file)
        case 'blowfish':
            decrypt_symmetric(BlowfishCipher(), key, key_file, in_file, out_file)
        case 'rc4':
            decrypt_symmetric(RC4Cipher(), key, key_file, in_file, out_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cipher', choices=['rsa', 'rc4', 'blowfish'], required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true')
    group.add_argument('-d', '--decrypt', action='store_true')

    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('-k', '--key', type=str)
    key_group.add_argument('--keyfile', type=str)

    parser.add_argument('--in', type=str, required=True)
    parser.add_argument('--out', type=str)

    args = vars(parser.parse_args())

    if args['encrypt']:
        encrypt(args['cipher'], args['key'], args['keyfile'], args['in'], args['out'])
    else:
        decrypt(args['cipher'], args['key'], args['keyfile'], args['in'], args['out'])


if __name__ == '__main__':
    main()
