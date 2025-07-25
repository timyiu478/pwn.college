---
tags: ["Cryptography", "Diffle-Hellman", "AES"]
title: "Diffle-Hellman Key Exchange Protocol"
description: Diffle-Hellman Key Exchange Protocol
reference: https://pwn.college/intro-to-cybersecurity/cryptography/
---

# DHKE

## Description

So, you now (hopefully!) understand the use of AES and the various hurdles, but there has been one thing that we have not considered. If person A (commonly refered to as Alice) wants to encrypt some data and send it to person B (commonly refered to as Bob) using AES, they must first agree on a key. If Alice and Bob see each other in person, one might write the key down and hand it to the other. But this rarely happens --- typically, the key must be established remotely, with Alice and Bob on either end of a (not yet encrypted!) network connection. In these common cases, Alice and Bob must securely generate a key even if they are being eavesdropped upon (think: network sniffing)! Fun fact: typically, the eavesdropper is referred to as Eve.

An "oldie but goodie" algorithm for generating a secret key on a non-secret communication channel is the Diffie-Hellman Key Exchange! DHKE uses the power of mathematics (specifically, Finite Fields) to come up with a key. Let's take it step by step:

First, Alice and Bob agree on a large prime number p to define their Finite Field (e.g., all further operations occur modulo p: a context where numbers go from 0 to p-1, and then loop around), along with a root g, and exchange them in the open, content to let Eve see them.
Then, Alice and Bob each generate a secret number (a for Alice's and b for Bob's). These numbers are never shared.
Alice computes A = (g ** a) mod p (g to the a power modulo p) and Bob computes B = (g ** b) mod p. Alice and Bob exchange A and B in the open.
At this point, Eve will have p, g, A, and B, but will be unable to recover a or b. If it wasn't for the finite field, recovering a and b would be trivial via a logarithm-base-g: log_g(A) == a and log_g(B) == b. However, this does not work in a Finite Field under a modulo because, conceptually, we have no efficient way to determine how many times the g ** a computation "looped around" from p-1 to 0, and this is needed to compute the logarithm. This logarithm-in-a-finite-field problem is called the Discrete Logarithm, and there is no efficient way to solve this without using a quantum computer. Quantum computers' ability to solve this problem is the most immediate thing that makes them so dangerous to cryptography.
Alice calculates s = (B ** a) mod p, and since B was (g ** b) mod p, this results in s = ((g ** b) ** a) mod p or, applying middle school math, s = (g ** (b*a)) mod p. Bob calculates s = (A ** b) mod p, and since A was (g ** a) mod p, this results in s = (g ** (a*b)) mod p. Since a*b == b*a, the s values computed by both Bob and Alice are equal!
Eve cannot compute s because Eve lacks a or b. Eve could compute A ** B == g ** a ** g ** b, which reduces to something like g ** (a*(g**b)) and doesn't get Eve any closer to s! Eve could also compute A * B == (g ** a) * (g ** b) == g ** (a+b), but again, this is not the s == g ** (a*b) that Bob and Alice arrived at. Eve is out of luck!
Because A and B are public, they are termed public keys, with a and b being private keys. Furthermore, you may noticed in this level that the prime number p that we use is hardcoded and, in fact, there are recommended DHKE for many bitsizes. The standardization of these primes allows Alice and Bob to just publish A and B (though, in practice, p is also transmitted to support the use of different ps in certain scenarios).

In this challenge you will perform a Diffie-Hellman key exchange. Good luck!

## Solution

1. generate private key b
2. share B = g^b mod p
3. shared key = A^b mod p = g^(ab) mod p

```python
>>> p = bytes.fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df2\
5f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c5\
5d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec0b\
a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff")
>>> import random
>>> b = random.randint(0, int.from_bytes(p, "little"))
>>> g = 0x2
>>> b = random.randint(0, int.from_bytes(p, "big"))
>>> B = pow(g, b, int.from_bytes(p, "big"))
>>> B.to_bytes(256, "big").hex()
'ec335df1deaa6d058bc02731adbbe496638cc2828eeb03b49a7bed6dabf339bceb2928e80716315c6791fd1a5df7f17a86b0273fda2949049e15f8859db851489497e8bb1f1b16f432f50a3443d688342a98d12ea6112eb3d7fdc2897292cafe489e95f7921d1af4ae7b218ca67f28ce11ff0a73ae3af9146a714721c388ba0404ec90755efb4131ff2cb3c867349c38cc0ee12c99ee54fac4c05c8b687e4afc609705a55c82458884e399a22dab86447c7c64cc94578efcb7d4a31fdf8eeb223753b5e3349da6963caf2a22afef567d757263557bce5828fb02cc034a9168cb9547d9d2252432d93fd7313fd1c708512f555bb9321ed4b3b74f15cc50946c3a'
>>> A = bytes.fromhex("85aa81433b427ec183b38137cf4ebb49ce9a36f979946ac0929064b2bf14b3f21d0fabf72658d88011bd3e3370b04733a36ead6627d998258c192fc23a\
4d0e2d9e32e3bd35d599034b8c2cf53125cdb7f694de474faa2bbab1ba3e17072c3f89f8a2bd8487cd16dfda6d9d926aedb5578cddaf4d917358328f6f436084032302c2491cd9e0a\
2ebec755b59d7f08b29d8b23aab91fe9b95b21fcf9e0835ff2dadac8d7fe242495c519873a09e05f4e585c9a3b8acf9976a3ed995b4ec7fb598272f5abf697f904d21e165fe9db7cc\
d36b0f6a361259603074fe0392367903aba62a03486e020d2a0715cffba5a3dae69b5ccbd73a4a3b1a23979d097984cd72ad")
>>> s = pow(int.from_bytes(A, "big"), b, int.from_bytes(p, "big"))
>>> s.to_bytes(256, "big").hex()
'7a661ebc605f90f959b48d225ad4dc8a83b013a081a55f902bb2ad45176c7256f2cad651aca433bab97f61706a841764423b5eeb613eabf34063f4b2f80e880063e932d52b9ed76ba2c092e54aeec8a13bf16560a6122259d486952e3682cdb17af250beb9da0ccfc5a5e1a5c28220ba055f7f517cf840146ac1e4c05cab2461a1e22045640f518abc5e3f5bd693b6feb325920868e4479ce3fa8af2211ba08502a02da8ef575594cff25f94e8dc6bec1fae21d541fd176507a7049bc377cd4aef4158e5c20ea58229c7f0f8249848901190638a83dc99196b760374e265b9f1ef63d99bb028814b4b4055d243b71e9942733a6bf9d01f096db34f73b78f6e75'
```

---

# DHKE-AES

## Description

You might have noticed that DH doesn't actually allow you to encrypt data directly: all it does is facilitate the generation of the same secret value for both Alice and Bob. This value cannot be chosen, what Alice and Bob get for s is uniquely determined by the values of a, b, p, and g!

This single-secret nature isn't necessarily a drawback of DHKE. That's just what it's for: letting you exchange a secret for further use.

So how do Alice and Bob actually exchange information using DHKE? Well, the hint is in the name: Diffie-Hellman Key Exchange. That secret value, of course, can be used as a key for, e.g., a symmetric cipher, and information can be encrypted with that cipher between Alice and Bob!

Armed with your knowledge of DHKE, you will now build your first cryptosystem that resembles something real! You'll use DHKE to negotiate an AES key, and the challenge will use that key to encrypt the flag. Decrypt it, and win!

## Solution

1. generate shared key s
2. map s -> AES key : `key = s.to_bytes(256, "little")[:16]`
3. AES Decrypt

```python
>>> import random
>>> p = bytes.fromhex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df2\
5f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c5\
5d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07\
a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff")
>>> g = 0x2
>>> A = bytes.fromhex("60916bac9aa483b3c3e07164f3b970404f0d389f7a2a8859e3b4dc034966ff5684f4d8955cc814608ab927afdfeba126a5519f2a301b58b07c5edbca51\
53b0361c93ff16024ecbc595373ad92296569ac935eb04718d7912ebc637bc2234ebde1231350182f7bfa92abf878e88ca12883fb1c516621563a554dfcafe39b5de80db4144c8244\
eb064ae473fe67006545dda7def50ee657a25ca9dd3edf03183c6eef7ea4c035c8583072f47d420dca2c3980087a3d921c3c753f0923053017b0c091818f5d00be4c73e5ec6d77954\
ff85dfa44dc8ae40f6b508c9d6f5b97f3d7afa009b386b6ede32f65a784b16d762f781b04fd809b556e3f5e39d187ad0b7b9")
>>> b = random.randint(0, int.from_bytes(p, "big"))
>>> B = pow(g, b, int.from_bytes(p, "big"))
>>> B.to_bytes(256, "big").hex()
'aa6196db27089df07336510f419c43a196cc4c9aefe704b6c744346c40053d7b2945bd06ec15ddaf76827904a233ade1626759c6a23c27eba94f85b12c75ca7ede2f31f31cba40531036ab22e0dd819199e433e6474f697a8b4d56e2456386c3e517b354d0a041c6a174ab452874a0174a52ac3f25b7ceef33e3250a82ea2d0b695aa194489cb2c088a59923c5a2fde8c8409a7e9b4f56f5d4e79ed0a09ce38ba1c4f8c52a157036730f8b027fe5bf80ecfb09d9a1910a9fa751159fff5ff272ceaeabff9c945084d475c2fab1772c6e61c86529519e2e5922dd0347423bb983386ef09567cec7a7c719e485a7b36ee8359b35976ea0ad79d27e9036a075cf3c'
>>> flag_cipher = bytes.fromhex("81910334f05fc2d1fda58e0838eb81bd2412f8b7d7e32adb30905c8b71da6322f9f0ba3e31fa8c53d87477278ab0f6ed48bd3a12dcda78cf\
d891e907a8118f6bc75eeb546b0c68d25a6f6fbeefd9c8c4")
>>> from Crypto.Cipher import AES
>>> s = pow(int.from_bytes(A, "big"), b, int.from_bytes(p, "big"))
>>> key = s.to_bytes(256, "little")[:16]
>>> cipher = AES.new(key, AES.MODE_CBC)
>>> cipher.decrypt(flag_cipher)
```
