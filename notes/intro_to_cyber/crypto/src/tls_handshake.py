from base64 import b64encode, b64decode
from sympy import primerange, randprime
import random
import json
from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Util.Padding import pad, unpad

root_key_d = bytes.fromhex(input("Root key d: "))

root_cert = json.loads(b64decode(input("root cert (b64): ")))

root_cert_signature = b64decode(input("root cert signature (b64): "))

dh_A = int.from_bytes(bytes.fromhex(input("Deffie Hellman A: ")), "big")

# Deffie Hellman
dh_p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
dh_g = 2

# RSA
p = randprime(2**300, 2**500)
q = randprime(2**300, 2**500)
n = p * q
e = randprime(2**6, 2**13)
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)


# User Certificate
user_name = input("User Cert Name: ")
user_cert = {
    "name": user_name,
    "key": {
        "e": e,
        "n": n,
    },
    "signer": "root"
}

# Deffie Hellman Key Generation
dh_b = random.randint(2**1024, dh_p)
dh_B = pow(dh_g, dh_b, dh_p)
dh_s = pow(dh_A, dh_b, dh_p)
print("DH B: ", dh_B.to_bytes(256, "big").hex())

# AES
key = SHA256Hash(dh_s.to_bytes(256, "little")).digest()[:16]
cipher_encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)


# User Certificate Signature
user_certificate_data = json.dumps(user_cert).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"),
    int.from_bytes(root_key_d, "big"),
    root_cert["key"]["n"]
).to_bytes(256, "little")

print("AES Encrypted User Certificate (b64):", b64encode(cipher_encrypt.encrypt(pad(user_certificate_data, cipher_encrypt.block_size))))
print("AES Encrypted User Certificate Signature (b64):", b64encode(cipher_encrypt.encrypt(pad(user_certificate_signature, cipher_encrypt.block_size))))

# User Signature
user_signature_data = (
        user_name.encode().ljust(256, b"\0") +
        dh_A.to_bytes(256, "little") +
        dh_B.to_bytes(256, "little")
    )
user_signature_hash = SHA256Hash(user_signature_data).digest()
signed_user_signature = pow(
    int.from_bytes(user_signature_hash, "little"),
    d,
    n
).to_bytes(256, "little")
encrypted_signed_user_signature = cipher_encrypt.encrypt(pad(signed_user_signature, cipher_encrypt.block_size))
print("AES Encrypted User Signature (b64):", b64encode(encrypted_signed_user_signature))

# TLS connection is established

# Ciphertext
flag_ciphertext = b64decode(input("Flag Ciphertext: "))

flag = unpad(cipher_decrypt.decrypt(flag_ciphertext), cipher_decrypt.block_size)

print("Flag:", flag)
