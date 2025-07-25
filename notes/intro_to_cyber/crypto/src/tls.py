from base64 import b64encode, b64decode
from sympy import primerange, randprime
import random
import json
from Crypto.Hash.SHA256 import SHA256Hash

root_key_d = bytes.fromhex(input("Root key d: "))

root_cert = json.loads(b64decode(input("root cert (b64): ")))

root_cert_signature = b64decode(input("root cert signature (b64): "))


# RSA
p = randprime(2**300, 2**500)
q = randprime(2**300, 2**500)
n = p * q
e = randprime(2**6, 2**13)
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)


# User Certificate
user_cert = {
    "name": "hi",
    "key": {
        "e": e,
        "n": n,
    },
    "signer": "root"
}


# User Certificate Signature
user_certificate_data = json.dumps(user_cert).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"),
    int.from_bytes(root_key_d, "big"),
    root_cert["key"]["n"]
).to_bytes(256, "little")

print("User Certificate:", b64encode(user_certificate_data))
print("User Certificate Signature:", b64encode(user_certificate_signature))

# Decrypt secret flag using user key

secret = int.from_bytes(b64decode(input("Input secret: ")), "little")

flag = pow(secret, d, n)

print("Flag: ", flag.to_bytes(256, "little"))



