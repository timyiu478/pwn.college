---
tags: ["Cryptography", "One Time Pad"]
title: "One-time Pad Tampering"
description: One-time Pad Tampering
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

So, the One Time Pad is proven to be secure... but only in the Confidential sense! It actually does not guarantee anything about Integrity. This challenge asks you: what if you could tamper with the message in transit? Think about how XOR works, and see if you can get the flag!

# Takeaway

Use authenticated encryption.

# Solution

1. read the python scripts

```python
hacker@cryptography~one-time-pad-tampering:/challenge$ cat worker
#!/opt/pwn.college/python

from Crypto.Util.strxor import strxor

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    cipher_len = min(len(data), len(key))
    plaintext = strxor(data[:cipher_len], key[:cipher_len])

    print(f"Hex of plaintext: {plaintext.hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == b"sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == b"flag!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
hacker@cryptography~one-time-pad-tampering:/challenge$ cat dispatcher
#!/opt/pwn.college/python

from Crypto.Util.strxor import strxor

key = open("/challenge/.key", "rb").read()
ciphertext = strxor(b"sleep", key[:5])

print(f"TASK: {ciphertext.hex()}")
```

2. run dispatcher to get the ciphertext

```
./dispatcher
TASK: b6012a0eb7
```

3. decrypt(ciphertext xor sleep xor flag!, key) = sleep xor sleep xor flag! = flag!

```python
>>> ciphertext = bytes.fromhex("b6012a0eb7")
>>> sleep = b"sleep"
>>> flag = b"flag!"
>>> "".join([hex(ciphertext[i] ^ sleep[i] ^ flag[i]) for i in range(len(flag))])
'0xa30x10x2e0xc0xe6'
```

```
TASK: a3012e0ce6
Hex of plaintext: 666c616721
Received command: b'flag!'
Victory! Your flag:
pwn.college{Ei9SREUb5k_TuxxCaN4mGjT92af.01M3kjNxwCM0YjMyEzW}
```
