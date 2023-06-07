import argparse
from ciphers.rsa import RSACipher


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--size', type=int, default=1024)
    parser.add_argument('--out', type=str, help="Path for the private key output file.")
    parser.add_argument('--pubout', type=str, help="Path for the public key output file.")

    args = parser.parse_args()

    private, public = RSACipher.gen_keypair(args.size)
    if args.out is None:
        print(private.export_key())
    else:
        private.export_to_file(args.out)
        print(f'Private key generated and saved to {args.out}')

    if args.pubout is None:
        print(public.export_key())
    else:
        public.export_to_file(args.pubout)
        print(f'Public key generated and saved to {args.pubout}')


if __name__ == '__main__':
    main()
