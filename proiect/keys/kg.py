#!/usr/bin/env python3
"""
Generate a 1024-bit RSA key-pair and dump it in the tiny-hex format
expected by the C project:

    rsa_pub.key   :  n=<hex>  e=<hex>
    rsa_priv.key  :  n=<hex>  e=<hex>  d=<hex>
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ----------------------------------------------------------------------
# helper: convert int -> hex without 0x prefix and without leading '00'
# ----------------------------------------------------------------------
def int_to_hex(i: int) -> str:
    h = f"{i:x}"                # hex without 0x
    if len(h) % 2:              # pad to even length
        h = "0" + h
    return h.lstrip("0") or "0" # remove leading 00 bytes

# ----------------------------------------------------------------------
# 1. generate key pair (1024 bits is enough for the assignment)
# ----------------------------------------------------------------------
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
    backend=default_backend()
)

priv_numbers = key.private_numbers()
pub_numbers  = key.public_key().public_numbers()

n_hex = int_to_hex(pub_numbers.n)
e_hex = int_to_hex(pub_numbers.e)
d_hex = int_to_hex(priv_numbers.d)

# ----------------------------------------------------------------------
# 2. write files
# ----------------------------------------------------------------------
with open("rsa_pub.key", "w") as fpub:
    fpub.write(f"n={n_hex}\n")
    fpub.write(f"e={e_hex}\n")

with open("rsa_priv.key", "w") as fpriv:
    fpriv.write(f"n={n_hex}\n")
    fpriv.write(f"e={e_hex}\n")
    fpriv.write(f"d={d_hex}\n")

print("Generated rsa_pub.key and rsa_priv.key – Done.")
