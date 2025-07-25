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


