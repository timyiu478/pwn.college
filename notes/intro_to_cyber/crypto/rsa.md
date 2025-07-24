---
tags: ["Cryptography"]
title: "RSA"
description: RSA
reference: https://pwn.college/intro-to-cybersecurity/cryptography/
---

# 1

## Description

Diffie-Hellman allow Alice and Bob to generate a single (but uncontrolled) shared secret with no pre-shared secret information. Next, we'll learn about another cryptosystem, RSA (Rivest–Shamir–Adleman), that allows Alice and Bob to generate arbitrary amounts of controlled messages, with no pre-shared secret information!

RSA uses a clever interaction of modular exponentiation (which you've experienced in DH) and Euler's Theorem to give Bob or Alice asymmetric control over an entire finite field. Alice generates two primes, p and q, and keeps them secret, then multiplies them to create n = p*q, which Alice publishes to define a Finite Field modulo n. Euler's Theorem and knowledge of p and q gives Alice, and only Alice, full abilities within this specific field (which is a difference from DH, where all actors have equal capabilities in the field!).

Euler's Theorem tells us that operations in an exponent of a field modulo p*q (e.g., the e*d of m**(e*d) mod n) take place in the field of (p-1)*(q-1). The why of this theorem is some advanced math stuff that, to be honest, few people understand, but the results are interesting. Computing (p-1)*(q-1) is trivial for Alice (armed with knowledge of p and q) but impossible to anyone else (assuming that p and q are large), because the human race lacks an efficient algorithm to factor products of large prime numbers!

Recall that e*d in the exponent of m**(e*d) mod n? For any e, knowing (p-1)*(q-1) allows Alice to compute a d such that e*d == 1. While this seems silly, it is the core of RSA. Alice chooses a number e (typically fairly small to reduce computation costs, but not too small to cause certain security issues) and computes the corresponding multiplicative inverse d. This leads to encryption of plaintext m (m**e mod n == c) and decryption! c**d mod n == (m**e)**d mod n == m**(e*d) mod n == m**1 mod n == m. Rather than DH's single and uncontrolled s, RSA messages m can be chosen arbitrarily (up to the size of n, as the field is unable to represent larger numbers).

RSA is asymmetric. Alice shares n and e as the public key, and keeps d as the private key. Knowing n and e, Bob can encrypt messages and send them to Alice, and only Alice can decrypt them. Since e*d == d*e, Alice can use d to encrypt messages, but anyone can decrypt them, since e is public. This might sound silly, but it is useful for, e.g., attesting that a given message could come only from Alice, since knowledge of d is required for this.

To respond to Bob, Alice would need Bob's own public key, which would be Bob's n (different from Alice's n, using Bob's own secret p and q!) and e (which is typically the same smallest-safe value, currently 65537 but subject to change as new attacks are found).

In this challenge you will decrypt a secret encrypted with RSA (Rivest–Shamir–Adleman). You will be provided with both the public key and private key this time, to get a feel for how all this works. Go for it!

## Solution

1. get the ciphertext and the RSA keys

```
hacker@cryptography~rsa-1:/challenge$ ./run
(public)  n = 0xd1e9d726ea1518004f78edc89f440d2e55da3cf239a9aba83403b4053652c1475a97d95839d8b717ab52739fa0e511595388ff4c00912d986a1a846f0661e519b98d1067cff7245a4616be47528e1224d292e6b8d228eb1c8886455045f70c6e4b729d1e6573fb5b962ffc67d2bccbc59002aec2c0f7edb80bc6d4eb3c8da372d25d39cee2ee344946f79c3a143aff30639190f889adabcf00594ab7e231fae7ce2d4b68973ecd2831820676f68494307ac5e32a472d6179b5244e6279964a46082615c6eb10c0f1a05a22203f4d85047fee33a67f031ff63418a762f0323f77e4f21ff035b83a4eb326d75d0a05e01afc3e1051725bd3b37de4786fb6ce81a1
(public)  e = 0x10001
(private) d = 0x14f00891c14a7d0e790290f0bf5157c3b2910041c3ba2ebe5cc52b77122f9a1db386600fae444ec95afff0410db38ffb88950fc425af8b00734d734d70140c371f74935803071ac8c8942ec5d0abcc355d130e7f4911e98b4e4e5db950b2599cee310f573a504b5ce332f7fa2d8df4b96ca9d1e27174cc59241510517847a27ce4b676cadb2a31f6254a7678f038a115d7a06beb16b6f50d6a8aefa119e40285102ff669c996c4694bdf15b8413e15813cc70a8d228dfd47388e7fe5a63f1d8c6e614ea65fc5704ff619c1c1eab4ec8af91eb37733d81eee0477dd381a11d923a77f1d616c2d36e77f5774a7d49009630e8f17cfaabd48cc68e5bd0d0018f9
Flag Ciphertext (hex): 324846e35361569c14762e8ab65d351e4c8cc263973c52737cdaacd6779562099ff8c44af69b91d700048b3a65497ac3a72d74f43a0b0441bb1b609512b7eb1352dc597186e00f2fecf9beed3b88e2fc3b914d45ff11f74cadd8d22a73c31419bce8f1ce206cd18ef8425bb32f93213f13d7d6e13bc35a0d6d3b131ef0d983154df1ae316fc9eb1112de213e5769e82ed9e6a0d2de816c3487c6369eed2c250ef7be9fa1e9aa023a294df40f50d78d9906a4865236d948c7d5f6c2bc82e1fb2daa97e793dcb349d45c8c89e88ece911d857051da38ea4490c8a6bf4e547af2fd7d1433eb80afed4cc88309276415f41b3f4b330fc1d8ba6dd8bd47afdba48c79
```

2. decrypt

```
>>> d = bytes.fromhex("14f00891c14a7d0e790290f0bf5157c3b2910041c3ba2ebe5cc52b77122f9a1db386600fae444ec95afff0410db38ffb88950fc425af8b00734d734d70140c371f74935803071ac8c8942ec5d0abcc355d130e7f4911e98b4e4e5db950b2599cee310f573a504b5ce332f7fa2d8df4b96ca9d1e27174cc59241510517847a27ce4b676cadb2a31f6254a7678f038a115d7a06beb16b6f50d6a8aefa119e40285102ff669c996c4694bdf15b8413e15813cc70a8d228dfd47388e7fe5a63f1d8c6e614ea65fc5704ff619c1c1eab4ec8af91eb37733d81eee0477dd381a11d923a77f1d616c2d36e77f5774a7d49009630e8f17cfaabd48cc68e5bd0d0018f9")
>>> cipher = bytes.fromhex("324846e35361569c14762e8ab65d351e4c8cc263973c52737cdaacd6779562099ff8c44af69b91d700048b3a65497ac3a72d74f43a0b0441bb1b609512b7eb1352dc597186e00f2fecf9beed3b88e2fc3b914d45ff11f74cadd8d22a73c31419bce8f1ce206cd18ef8425bb32f93213f13d7d6e13bc35a0d6d3b131ef0d983154df1ae316fc9eb1112de213e5769e82ed9e6a0d2de816c3487c6369eed2c250ef7be9fa1e9aa023a294df40f50d78d9906a4865236d948c7d5f6c2bc82e1fb2daa97e793dcb349d45c8c89e88ece911d857051da38ea4490c8a6bf4e547af2fd7d1433eb80afed4cc88309276415f41b3f4b330fc1d8ba6dd8bd47afdba48c79")
>>> n = bytes.fromhex("d1e9d726ea1518004f78edc89f440d2e55da3cf239a9aba83403b4053652c1475a97d95839d8b717ab52739fa0e511595388ff4c00912d986a1a846f0661e519b98d1067cff7245a4616be47528e1224d292e6b8d228eb1c8886455045f70c6e4b729d1e6573fb5b962ffc67d2bccbc59002aec2c0f7edb80bc6d4eb3c8da372d25d39cee2ee344946f79c3a143aff30639190f889adabcf00594ab7e231fae7ce2d4b68973ecd2831820676f68494307ac5e32a472d6179b5244e6279964a46082615c6eb10c0f1a05a22203f4d85047fee33a67f031ff63418a762f0323f77e4f21ff035b83a4eb326d75d0a05e01afc3e1051725bd3b37de4786fb6ce81a1")

>>> pow(int.from_bytes(cipher, "little"), int.from_bytes(d), int.from_bytes(n)).to_bytes(256, "little").decode("ascii")
```

---

# 2

## Description

Alice's superpower under modulo n comes from knowledge of p and q, and, thus, the ability to compute the multiplicative inverse of e in the exponent. One worry of everyone who uses RSA is that their n will get factored, and attackers will gain p and q.

This is not an unreasonable worry. While we believe that factoring is hard, we have no actual proof that it is. It is not outside of the realm of possibility that, tomorrow, Euler 2.0 will publish an algorithm for doing just this. However, we do know that functional quantum computers can factor: Euler 2.0 (actually, Peter Shor) already came up with the algorithm! When quantum computers get to a sufficient power level, RSA is cooked.

In this challenge, we give you the quantum computer (or, at least, we give you n's factors)! Use them to decrypt the flag that we encrypted with RSA (Rivest–Shamir–Adleman).

## Solution

1.

```
hacker@cryptography~rsa-2:/challenge$ ./run
e = 0x10001
p = 0xe98b06718cddd3d817215b3dccdc0a19ca2c1479a6f9885d0434462f65d35fc973273746235e4c932c463e4ea60958fde081cfe5adde7b30162e1839a8f549c9b4bd62fff4f1edcb661aec316110520230ec910cd016284ae9f85a920a2fa95f90ba2cea7efe4be9d9e1a03e569c739e421817d06bb49756992c9c8fbdad1a7f
q = 0xef18c2a2a4477304c5ddc428c5914c497dd1e2faa23feac98e764dbac589925c8b9dd484fc0df10258a169c7bcd6e299f0f720417a0d1e72cfdfc48013bd454c145cd4ecc737d58a5be16f84b90bf31505b4c9b963d9475d7bd4245c63040d6f1ded414d2c135f61eeeea009efacb3d366292410ebedb64821aab6b70603bb25
Flag Ciphertext (hex): 700fdae4ce82dbdb90b1fbe2d4b3dcf47a68b03f0fe799f4497f0fc841886241a45805ff4027776cfe6f1366470a162fedc6ab022575a0611fa68f171551ff31c96961df2dd9f1e3827695e4f2c061c4fdecd217690c5d5e1db7238b862eea6ff5a06b563df8efa285613d89d01e27c950b1f39ce996cf21bfa93ac460f159846be3d823b780c4d06b56dde880318cf0290becb4844c9184b21f627baed2389fbc72a426db5ee9ea76b9f8c10848ca10dcbc32d1b02961ac9b33ce1acc9eb0c7ac535b63134a51a2da919dfb408f46834a550853f2d6cd4d3229c443534a58aca87900b0e9f133e610b7ddf2bf89b412fdae3aef6e0034cbda0ae3713fb57510
```

2. 

- we can get phi(n) by computing (p-1) * (q-1)
- then we can get d by computing e ^ -1 mod phi(n)

```
>>> e = bytes.fromhex("010001")
>>> p = bytes.fromhex("e98b06718cddd3d817215b3dccdc0a19ca2c1479a6f9885d0434462f65d35fc973273746235e4c932c463e4ea60958fde081cfe5adde7b30162e1839a8f549c9b4bd62fff4f1edcb661aec316110520230ec910cd016284ae9f85a920a2fa95f90ba2cea7efe4be9d9e1a03e569c739e421817d06bb49756992c9c8fbdad1a7f")
>>> q = bytes.fromhex("ef18c2a2a4477304c5ddc428c5914c497dd1e2faa23feac98e764dbac589925c8b9dd484fc0df10258a169c7bcd6e299f0f720417a0d1e72cfdfc48013bd454c145cd4ecc737d58a5be16f84b90bf31505b4c9b963d9475d7bd4245c63040d6f1ded414d2c135f61eeeea009efacb3d366292410ebedb64821aab6b70603bb25")
>>> cipher = bytes.fromhex("700fdae4ce82dbdb90b1fbe2d4b3dcf47a68b03f0fe799f4497f0fc841886241a45805ff4027776cfe6f1366470a162fedc6ab022575a0611fa68f171551ff31c96961df2dd9f1e3827695e4f2c061c4fdecd217690c5d5e1db7238b862eea6ff5a06b563df8efa285613d89d01e27c950b1f39ce996cf21bfa93ac460f159846be3d823b780c4d06b56dde880318cf0290becb4844c9184b21f627baed2389fbc72a426db5ee9ea76b9f8c10848ca10dcbc32d1b02961ac9b33ce1acc9eb0c7ac535b63134a51a2da919dfb408f46834a550853f2d6cd4d3229c443534a58aca87900b0e9f133e610b7ddf2bf89b412fdae3aef6e0034cbda0ae3713fb57510")
>>> phi_n = (int.from_bytes(p) - 1) * (int.from_bytes(q) - 1)
>>> d = pow(int.from_bytes(e), -1, phi_n)
>>> n = (int.from_bytes(p)) * (int.from_bytes(q))
>>> pow(int.from_bytes(cipher, "little"), d, n).to_bytes(256, "little").decode("ascii")
```

---

# 3

## Description

In this challenge you will complete an RSA challenge-response. You will be provided with both the public key and private key.

## Solution

---

# 4

## Description

In this challenge you will complete an RSA challenge-response. You will provide the public key.

## Solution

---

# Signature

## Description

So by using d, Alice can encrypt data that (because n and e are in the public key) anyone can decrypt... This might seem silly, but it actually enables a capability that we haven't yet seen in the module: the ability to attest to multiple people that a message came from Alice. This can serve as a sort of cryptographic version of a pen-and-ink signature and, in fact, it is called a signature!

This level will explore one application (and pitfall) of RSA signatures. Recall that c == m**e mod n, and recall from middle school that (x**e)*(y**e) == (x*y)**e. This holds just as well in mod n, and you can probably see the issue here...

This level gives you a signing oracle. Go use it to craft a flag command!

## Solution

### 1. Read the python code

dispatcher: 

- it can help us to sign any message excep the `flag` message

```python
import sys

from base64 import b64encode, b64decode

n = int(open("/challenge/key-n").read(), 16)
d = int(open("/challenge/key-d").read(), 16)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} [command-b64]")
    sys.exit(1)

command = b64decode(sys.argv[1].strip("\0"))

if b"flag" in command:
    print(f"Command contains 'flag'")
    sys.exit(1)

signature = pow(int.from_bytes(command, "little"), d, n).to_bytes(256, "little")
print(f"Signed command (b64): {b64encode(signature).decode()}")
```

worker:

- print out `/flag` if the signed message is `flag`

```python
import sys

from base64 import b64decode

n = int(open("/challenge/key-n").read(), 16)
e = int(open("/challenge/key-e").read(), 16)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} [signature-b64]")
    sys.exit(1)

signature = b64decode(sys.argv[1])
c = int.from_bytes(signature, "little")
assert c < n, "Message too big!"
command = pow(c, e, n).to_bytes(256, "little").rstrip(b"\x00")

print(f"Received signed command: {command}")
if command == b"flag":
    print(open("/flag").read())
```

### 2. get signed message of flag ^ 3 and flag ^ -2

```
>>> f = b"flag"
>>> n = int(open("/challenge/key-n").read(), 16)
>>> from base64 import b64decode
>>> from base64 import b64encode
>>> f3b64 = b64encode(pow(int.from_bytes(f, "little"), 3, n).to_bytes(256, "little"))
>>> fi2b64 = b64encode(pow(int.from_bytes(f, "little"), -2, n).to_bytes(256, "little"))
>>> signed_f3 = int.from_bytes(b64decode("Z6mi7k/jq7ALAylJMqlyIeaj646SkDkdZgsH+B/cT8JlSKamG+TE77bczQJef02RX9b4pqqR5X/pfpJEY8paOF4rQ02IraBt3fe4St7xy3JoVBaSA4reec+79snZo1pijNokT3mMpQvrE6xxP+87yKPLXPgxMSqMxzsIClpfqrLzBmOn/jXEyIa/IMN4cuqsPWEBtwdWfvHScMqvSineNyc447/XhSPguvsrIwsg6IXjlsRwN86GAfeZ7OrTHOWU7LnuwpKkY3B5iF8qt2/CtJJ2YDcfIhdOa84zKSvMR2zkkITETEexhJa6zkoRc4q0vrRe7TXxQwI8HMUmo84dow=="), "little")
>>> signed_fi2 = int.from_bytes(b64decode("pBlA7iUN/lYlYqVKBZY4DiePQmhilizHrM7FMP/Pfj77sSy/aeejsub5Xd/olX3/5xtd+301BDlpuO6BH05+APpZJWqm/GmJxM9dgNBQ4WjHVYtWKkMdBWbdyBD1By8ymssKyABGlZEa5RS8G3U4im3POiiDB0vIHzbxlUzbl5d3+QLkaVct4EO5+WDf0cJaxbb88KfmhV5mmwLWS+uCqRPCnVkkxeSIoggEcDDWSHTcdnVtqHUdBAn/canOs1vERozXdDdnjVYWaTRRqFesYxE6ZCXIWhEC4TmFGrQLtLVprRZ/kW02RQBS2UEDJC/pXo2Y6ZOFpJ2yL4r7HsYvGQ=="), "little")
```

### 3. compute signed flag ^ 3 * signed flag ^ -2 mod N

```
>>> b64encode(((signed_f3 * signed_fi2) % n).to_bytes(256, "little"))
b'iGl1pWZpF/7tPTioKBELkZA5r4ubdsMEbS7WskJ79bgj8f92s1w1XYPAX3GknsACMQzlk4hRhFiYcLbqn89vP5ongdQqFWeHupRV30T2mRYFRQU5mmzQMeFX20iyzUiiV9ig/wvCWcd7Q8DJaPRCu/sYTHXvASv+C57A4jos5PGW2erjKaE2ft0q07bqwyWb9Sidi083xXxiMsZmmXtTjVyrtbXGPYpsnDie0RWRYNuNOpyA9pshQv3hEBXzTDedsSqh3A2FPnYoZLKjqpzxxS5wfmQSVEwTYL0tSSMpmV4jKpb34s8lt13uDe2hCinDnIYQ4ItSlW2i8EZOMjDXlA=='
```
