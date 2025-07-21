---
tags: ["Cryptography", "Proof Of Work"]
title: "SHA"
description: SHA
reference: https://pwn.college/intro-to-cybersecurity/cryptography/
---

# 1

## Description

As you saw, raw RSA signatures are a bad idea, as they can be forged. In practice, what people sign are cryptographic hashes of things. A hash is a one-way function that takes an arbitrary amount of input (e.g., bytes or gigabytes or more) and outputs a short (e.g., 32 bytes) of output hash. Any changes in the input to the hash will diffuse all over the resulting cryptographic hash in a way that is not reversible.

Thus, secure hashes are a good representation for the original data: if Alice signs a hash of a message, that message can be seen as being signed as well. Better yet, since hashes are not controllably reversible or modifiable, an attacker being able to modify a hash does not allow them to forge a signature on a new message.

The bane of cryptographic hashing algorithms is collision. If an attacker can craft two messages that hash to the same thing, the security of any system that depends on the hash (such as the RSA signature scheme described above) might be compromised. For example, consider that the security of bitcoin depends fully on the collision resistance of SHA256...

While full collisions of SHA256 don't exist, some applications use partial hash verification. This is not a great practice, as it makes it easier to brute-force a collision.

In this challenge you will do just that, hashing data with a Secure Hash Algorithm (SHA256). You will find a small hash collision. Your goal is to find data, which when hashed, has the same hash as the secret. Only the first 3 bytes of the SHA256 hash will be checked.

## Solution

1. we know the size of the flag is 60 bytes

```
hacker@cryptography~sha-1:~$ ls -alt /flag
-r-------- 1 root root 60 Jul 21 08:04 /flag
```

2.

```python
from random import randbytes
import hashlib

target = input("target: ")
r = randbytes(60)
h = hashlib.sha256(r).hexdigest()[:6]
while h != target:
    r = randbytes(60)
    h = hashlib.sha256(r).hexdigest()[:6]

print(r.hex())
```

---

# 2 

## Description

In this challenge you will hash data with a Secure Hash Algorithm (SHA256). You will compute a small proof-of-work. Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.


## Solution

1. read the proof-of-work challenge source code

```python
def input_b64(name):
    data = input_(f"{name} (b64)")
    try:
        return base64.b64decode(data)
    except base64.binascii.Error:
        print(f"Failed to decode base64 input: {data!r}", file=sys.stderr)
        exit(1)

def level10():
    """
    In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
    You will compute a small proof-of-work.
    Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.
    """
    difficulty = 2

    challenge = get_random_bytes(32)
    show_b64("challenge", challenge)

    response = input_b64("response")
    if SHA256Hash(challenge + response).digest()[:difficulty] == (b'\0' * difficulty):
        show("flag", flag.decode())
```

2. do the work

```python
import base64
from Crypto.Hash.SHA256 import SHA256Hash

def increment_byte_array(byte_arr):
    byte_arr = bytearray(byte_arr)  # Make it mutable
    carry = 1

    for i in reversed(range(len(byte_arr))):  # Start from least significant byte
        if carry == 0:
            break
        new_val = byte_arr[i] + carry
        byte_arr[i] = new_val % 256
        carry = new_val // 256

    # Optional: if carry is still 1, we overflowed—add a new byte
    if carry:
        byte_arr = bytearray([1]) + byte_arr

    return bytes(byte_arr)

chal = base64.b64decode(input("challenge: "))
difficulty = 2
r = bytes.fromhex("00")

while SHA256Hash(chal + r).digest()[:difficulty] != (b'\0' * difficulty):
    r = increment_byte_array(r)

print(base64.b64encode(r))
```
