---
tags: ["Cryptography"]
title: "TLS"
description: TLS
reference: https://pwn.college/intro-to-cybersecurity/cryptography/
---

# 1

## Description

In this challenge you will work with public key certificates. You will be provided with a self-signed root certificate. You will also be provided with the root private key, and must use that to sign a user certificate.

## Solution

1. what is root certificate

```json
{"name": "root", "key": {"e": 65537, "n": 27197886675598245858326236302788991640804181037808510135866017602073085198678617734662957565554487039292257018703951257131289090044813796490222034611404744228386801659116750074086983998306030187487071266269897749985667112984795383607395121464884055730629636957938260583280100512558214612825029458464659711285853811644873572013084553898904172504167466837486607558404414899305587756913134795882249486441303828180591826192166387807742234326323192635460932297299581189088448749627200051138066384779771483861451769651213960984510137428185096096147071541948937638002240804365011040638684971475267178856433085290092485003981}, "signer": "root"}
```

2. what is root certificate signature

```python
root_certificate_data = json.dumps(root_certificate).encode()
root_certificate_hash = SHA256Hash(root_certificate_data).digest()
root_certificate_signature = pow(
    int.from_bytes(root_certificate_hash, "little"),
    root_key.d,
    root_key.n
).to_bytes(256, "little")
```

3. Run [tls.py](src/tls.py).

---

# 2 

## Description

In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server. You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key. The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange. The server must complete the key exchange, and derive an AES-128 key from the exchanged secret. Then, using the encrypted channel, the server must supply the requested user certificate, signed by root. Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.

## Solution

1. read the `run` source code to see how the TLS client act in the TLS handshake

```python
def level14():
    """
    In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server.
    You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key.
    The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange.
    The server must complete the key exchange, and derive an AES-128 key from the exchanged secret.
    Then, using the encrypted channel, the server must supply the requested user certificate, signed by root.
    Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.
    """
    # 2048-bit MODP Group from RFC3526
    p = int.from_bytes(bytes.fromhex(
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
    g = 2

    show_hex("p", p)
    show_hex("g", g)

    root_key = RSA.generate(2048)

    show_hex("root key d", root_key.d)

    root_certificate = {
        "name": "root",
        "key": {
            "e": root_key.e,
            "n": root_key.n,
        },
        "signer": "root",
    }

    root_trusted_certificates = {
        "root": root_certificate,
    }

    root_certificate_data = json.dumps(root_certificate).encode()
    root_certificate_hash = SHA256Hash(root_certificate_data).digest()
    root_certificate_signature = pow(
        int.from_bytes(root_certificate_hash, "little"),
        root_key.d,
        root_key.n
    ).to_bytes(256, "little")

    show_b64("root certificate", root_certificate_data)
    show_b64("root certificate signature", root_certificate_signature)

    name = ''.join(random.choices(string.ascii_lowercase, k=16))
    show("name", name)

    a = getrandbits(2048)
    A = pow(g, a, p)
    show_hex("A", A)

    B = input_hex("B")
    if not (B > 2**1024):
        print("Invalid B value (B <= 2**1024)", file=sys.stderr)
        exit(1)

    s = pow(B, a, p)
    key = SHA256Hash(s.to_bytes(256, "little")).digest()[:16]
    cipher_encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
    cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)

    def decrypt_input_b64(name):
        data = input_b64(name)
        try:
            return unpad(cipher_decrypt.decrypt(data), cipher_decrypt.block_size)
        except ValueError as e:
            print(f"{name}: {e}", file=sys.stderr)
            exit(1)

    user_certificate_data = decrypt_input_b64("user certificate")
    user_certificate_signature = decrypt_input_b64("user certificate signature")
    user_signature = decrypt_input_b64("user signature")

    try:
        user_certificate = json.loads(user_certificate_data)
    except json.JSONDecodeError:
        print("Invalid user certificate", file=sys.stderr)
        exit(1)

    user_name = user_certificate.get("name")
    if user_name != name:
        print(f"Invalid user certificate name: `{user_name}`", file=sys.stderr)
        exit(1)

    user_key = user_certificate.get("key", {})
    if not (isinstance(user_key.get("e"), int) and isinstance(user_key.get("n"), int)):
        print(f"Invalid user certificate key: `{user_key}`", file=sys.stderr)
        exit(1)

    if not (user_key["e"] > 2):
        print("Invalid user certificate key e value (e > 2)", file=sys.stderr)
        exit(1)

    if not (2**512 < user_key["n"] < 2**1024):
        print("Invalid user certificate key n value (2**512 < n < 2**1024)", file=sys.stderr)
        exit(1)

    user_signer = user_certificate.get("signer")
    if user_signer not in root_trusted_certificates:
        print(f"Untrusted user certificate signer: `{user_signer}`", file=sys.stderr)
        exit(1)

    user_signer_key = root_trusted_certificates[user_signer]["key"]
    user_certificate_hash = SHA256Hash(user_certificate_data).digest()
    user_certificate_check = pow(
        int.from_bytes(user_certificate_signature, "little"),
        user_signer_key["e"],
        user_signer_key["n"]
    ).to_bytes(256, "little")[:len(user_certificate_hash)]

    if user_certificate_check != user_certificate_hash:
        print("Untrusted user certificate: invalid signature", file=sys.stderr)
        exit(1)

    user_signature_data = (
        name.encode().ljust(256, b"\0") +
        A.to_bytes(256, "little") +
        B.to_bytes(256, "little")
    )
    user_signature_hash = SHA256Hash(user_signature_data).digest()
    user_signature_check = pow(
        int.from_bytes(user_signature, "little"),
        user_key["e"],
        user_key["n"]
    ).to_bytes(256, "little")[:len(user_signature_hash)]

    if user_signature_check != user_signature_hash:
        print("Untrusted user: invalid signature", file=sys.stderr)
        exit(1)

    ciphertext = cipher_encrypt.encrypt(pad(flag, cipher_encrypt.block_size))
    show_b64("secret ciphertext", ciphertext)
```

2. write and run the [tls_handshake.py](src/tls_handshake.py) program

- 1) Diffie-Hellman Key Exchange, the subsequent communication will be AES encrypted by this session shared key
- 2) Tell user its RSA certificate and RSA certificate signature signed by root CA
- 3) Tell user its TLS session signature signed by its RSA private key
