import os
import logging
from multiprocessing import Pool
import plyvel as pl
from hashlib import sha256
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

# Set up logging
logging.basicConfig(level=logging.INFO)

def validate_input(input):
    if not isinstance(input, int):
        raise ValueError('Invalid input type')
    if not 1 <= input <= 2**256:
        raise ValueError('Input out of range')

def compute_rmd160(pubkey):
    """Compute the RIPEMD-160 hash of a public key."""
    sha = sha256(pubkey).digest()
    rmd160 = hashlib.new('ripemd160')
    rmd160.update(sha)
    return rmd160.hexdigest()

def compute_address(rmd160):
    """Compute the Bitcoin address corresponding to a given RIPEMD-160 hash."""
    version = b'\x00'  # Bitcoin mainnet version byte
    checksum = hashlib.sha256(hashlib.sha256(version + rmd160).digest()).digest()[:4]
    address = base58.b58encode(version + rmd160 + checksum)
    return address.decode()  # Decode bytes to string

def baby_step(start, end, db):
    """Compute the baby steps and store them in a database."""
    sk = SigningKey.from_secret_exponent(start, curve=SECP256k1)
    for i in range(start, end+1):
        pubkey = b'\x04' + sk.verifying_key.to_string()
        rmd160 = compute_rmd160(pubkey)
        with db.write_batch() as b:
            b.put(rmd160.encode(), str(i).encode())
        sk = SigningKey.from_secret_exponent(i+1, curve=SECP256k1)

def giant_step(start, end, db):
    """Compute the giant steps and look for matches in the database."""
    sk = SigningKey.from_secret_exponent(start, curve=SECP256k1)
    for i in range(start, end+1):
        pubkey = b'\x04' + sk.verifying_key.to_string()
        rmd160 = compute_rmd160(pubkey)
        if db.get(rmd160.encode()):
            logging.info(f'Match found: {rmd160}')
        sk = SigningKey.from_secret_exponent(i+1, curve=SECP256k1)

def main():
    """Main function."""
    try:
        db = pl.DB('bsgs.db', create_if_missing=True)
        with Pool(processes=8) as pool:
            pool.apply_async(baby_step, (2**65, 2**66, db))  # Baby steps range
            pool.apply_async(giant_step, (2**65, 2**66, db))  # Giant steps range
            pool.close()
            pool.join()
    except Exception as e:
        logging.error(f'An error occurred: {e}')
    finally:
        db.close()

if __name__ == '__main__':
    main()
