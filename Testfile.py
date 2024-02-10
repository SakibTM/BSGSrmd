import pytest
import os
from BSGS import compute_rmd160, compute_address

def test_compute_rmd160():
    pubkey = b'\x04' + os.urandom(64)
    rmd160 = compute_rmd160(pubkey)
    assert isinstance(rmd160, str)
    assert len(rmd160) == 40  # RIPEMD-160 hashes are 40 hex characters

def test_compute_address():
    rmd160 = bytes.fromhex('20d45a6a762535700ce9e0b216e31994335db8a5')
    address = compute_address(rmd160)
    assert isinstance(address, str)
    assert address.startswith('1')  # Bitcoin addresses start with '1'
