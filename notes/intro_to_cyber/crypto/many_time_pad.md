---
tags: ["Cryptography"]
title: "Many-Time Pad"
description: Many-Time Pad
reference: https://pwn.college/intro-to-cybersecurity/cryptography/
---

# Description

The previous challenge gave you the one time pad to decrypt the ciphertext. If you did not know the one time pad, and it was only ever used for one message, the previous challenge would be unsolvable! In this level, we'll explore what happens if the latter condition is violated. You don't get the key this time, but we'll let you encrypt as many messages as you want. Can you decrypt the flag?

Hint: think deeply about how XOR works, and consider that it is a distributative, commutative, and associative operation...

Hint: we recommend writing your solution in Python and using the strxor function that we use in the challenge! It makes life much simpler.

# Solution

1. read the python code

We can give an input to the program and the program will use the secret key to encrypt using XOR method.

```python
#!/opt/pwn.college/python

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

flag = open("/flag", "rb").read()

key = get_random_bytes(256)
ciphertext = strxor(flag, key[:len(flag)])

print(f"Flag Ciphertext (hex): {ciphertext.hex()}")

while True:
    plaintext = bytes.fromhex(input("Plaintext (hex): "))
    ciphertext = strxor(plaintext, key[:len(plaintext)])
    print(f"Ciphertext (hex): {ciphertext.hex()}")
```

2. pass the flag ciphertext as input and it should return the flag plaintext

```
hacker@cryptography~many-time-pad:/challenge$ ./run
Flag Ciphertext (hex): fdac3eb7588a6ee459c091dc0fa7137efe1e66c77a358b1bd0c87cc5b5a38446a49c015778bed95ec0988b6f7b8455146cefc3dbfba72c460a516370
Plaintext (hex): fdac3eb7588a6ee459c091dc0fa7137efe1e66c77a358b1bd0c87cc5b5a38446a49c015778bed95ec0988b6f7b8455146cefc3dbfba72c460a516370
Ciphertext (hex): 70776e2e636f6c6c6567657b7368546234564e495475384f45394156594c7237467a56767a51492e515831637a4d7a77434d30596a4d79457a577d0a
```

3. decode the hex to ascii

```
>>> hex_str = "70776e2e636f6c6c6567657b7368546234564e495475384f45394156594c7237467a56767a51492e515831637a4d7a77434d30596a4d79457a577d0a"
>>> ascii_str = bytes.fromhex(hex_str).decode('utf-8')
```
