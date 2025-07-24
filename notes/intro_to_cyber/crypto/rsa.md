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

1. challenge

```
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will complete an RSA challenge-response.
You will be provided with both the public key and private key.


e: 0x10001
d: 0xfee65aec964b7f448ceec37db9829e253571b2834a6cbe3ccac4a8446e70fcfd73b22e7740ebed8b19e3d42d472f89e767e62e29ecd9ae4453b25e4d3f09793d5b0e210351d78cc53105642b1e09ec640fb8a41b3002ab64e43b773e80599bd4d7e209e9fee6b03ba87684b99fff0b123fd1f5e2d33314f040feafc934a0507d348fb0363b3cf4fa74878865406cf11a12aa702989a35e7eee9e257b35b152b1a937b3f1d4550c65e9c8d8a6fc0abd9276088be30a1f8a7a1dd94526e6fe3689548577374bd2cff5e3b6f514bcaddf140a0491a2e040f9b6bab5b55fe311bd69430df751c813a9b1dc40a42585dfc1764299bc4487b5bfb315e2858e2affc69
n: 0x9fb9b9e2b0783498a61965fb6e1e31a893b388a48e65bf626dea40953063bccac9e7aa5582e6a5da8f0074976ec66c489cebc6fa88c9496f972d307e2d6312e2329176494301658d4e2089a8ed1130550d8d5bef67a6622452aca3ce0bdde127baf8dded98653c1784ea587d5572288e809a471ccc220d7ff8705c71c7a5dbdf3efd0ac60100a426ffb7b989170d8ea18f68d83d604c89169aa6d991a42acb96a6a9c50d185804f5dc9e1d75c56dcd9676358488fe5b93de6eb1e0d2736e7d6216a0a818d2c1796e06db880a75f83051f48937266184997d8b91d9091cb38799f2f298dbe1855f993b18c0a5309a0bfa6db877fbb95953ec499cda806ef34ecd
challenge: 0x1162029e5b2b0ff830a9a5d6968325cfce23201a66cb40ae136e7959e0555ce45046d6f579ecbd03eda47d9ff927d79662a06dc49f16177b42fdd7cccb18fbb063682468e46de6a8e64dc7b59e32cf6595fbc5ff23da4b94cfa513ac1dcb088ab61f0de65a732185c8a2511dc6b1f77be53f262f04bbb872ed4a259f2cdcc7b6d46ede29a54f1b9c74a8e624330866518b13041db84c4d45f8fdbb239781042d18b1d5712707374151b9890893517db8b27913d2a845c24eb2264b30eaeac9371acaa25382a20b7d08ecc9feeb42fd05f390fb0df9d3fec28cbc9a6962a9c97acbb497885b4378f407e74fa1e3a90f1484fd8d1dfac9863533bcabedb1c7c10c
response: 907fd0962d959a34dc1ee6ca96c18eac5bde28bb37a90d96457002a8329f0dd4d7e0842368c216a3b6e5ba753671be738b09bf7391e654374eadcba31e57e904ca5fcd2c8220d75e1001d81cb6e492371cf31a4b8e1589d379c5fc6fbc3650e016dae62ae1371a200885232fc492594d1f868b8dae20905017542bf0e94dff18e41ed033b65dbc3468c49f6902d22f8e3bef5b7844d7f43f4fc79ef05a884b5552ba45c16927d367cfb21254c40831a358f6e186812e12ecde37c4567cc862aa04757deea003a33fe023b5f3eff316b0d5b6b5fae3dd876da9c13eaf645cc7beaeeee447383f1cb3dd75d6df65da69cba0bd9797591e011844787788502971a1
```

2. response p

```
>>> d = bytes.fromhex("0fee65aec964b7f448ceec37db9829e253571b2834a6cbe3ccac4a8446e70fcfd73b22e7740ebed8b19e3d42d472f89e767e62e29ecd9ae4453b25e4d3f09793d5b0e210351d78cc53105642b1e09ec640fb8a41b3002ab64e43b773e80599bd4d7e209e9fee6b03ba87684b99fff0b123fd1f5e2d33314f040feafc934a0507d348fb0363b3cf4fa74878865406cf11a12aa702989a35e7eee9e257b35b152b1a937b3f1d4550c65e9c8d8a6fc0abd9276088be30a1f8a7a1dd94526e6fe3689548577374bd2cff5e3b6f514bcaddf140a0491a2e040f9b6bab5b55fe311bd69430df751c813a9b1dc40a42585dfc1764299bc4487b5bfb315e2858e2affc69")
>>> n = bytes.fromhex("9fb9b9e2b0783498a61965fb6e1e31a893b388a48e65bf626dea40953063bccac9e7aa5582e6a5da8f0074976ec66c489cebc6fa88c9496f972d307e2d6312e2329176494301658d4e2089a8ed1130550d8d5bef67a6622452aca3ce0bdde127baf8dded98653c1784ea587d5572288e809a471ccc220d7ff8705c71c7a5dbdf3efd0ac60100a426ffb7b989170d8ea18f68d83d604c89169aa6d991a42acb96a6a9c50d185804f5dc9e1d75c56dcd9676358488fe5b93de6eb1e0d2736e7d6216a0a818d2c1796e06db880a75f83051f48937266184997d8b91d9091cb38799f2f298dbe1855f993b18c0a5309a0bfa6db877fbb95953ec499cda806ef34ecd")
>>> c = bytes.fromhex("1162029e5b2b0ff830a9a5d6968325cfce23201a66cb40ae136e7959e0555ce45046d6f579ecbd03eda47d9ff927d79662a06dc49f16177b42fdd7cccb18fbb063682468e46de6a8e64dc7b59e32cf6595fbc5ff23da4b94cfa513ac1dcb088ab61f0de65a732185c8a2511dc6b1f77be53f262f04bbb872ed4a259f2cdcc7b6d46ede29a54f1b9c74a8e624330866518b13041db84c4d45f8fdbb239781042d18b1d5712707374151b9890893517db8b27913d2a845c24eb2264b30eaeac9371acaa25382a20b7d08ecc9feeb42fd05f390fb0df9d3fec28cbc9a6962a9c97acbb497885b4378f407e74fa1e3a90f1484fd8d1dfac9863533bcabedb1c7c10c")
>>> p = pow(int.from_bytes(c, "big"), int.from_bytes(d, "big"), int.from_bytes(n, "big"))
>>> p.to_bytes((p.bit_length() + 7) // 8, "big").hex()
'907fd0962d959a34dc1ee6ca96c18eac5bde28bb37a90d96457002a8329f0dd4d7e0842368c216a3b6e5ba753671be738b09bf7391e654374eadcba31e57e904ca5fcd2c8220d75e1001d81cb6e492371cf31a4b8e1589d379c5fc6fbc3650e016dae62ae1371a200885232fc492594d1f868b8dae20905017542bf0e94dff18e41ed033b65dbc3468c49f6902d22f8e3bef5b7844d7f43f4fc79ef05a884b5552ba45c16927d367cfb21254c40831a358f6e186812e12ecde37c4567cc862aa04757deea003a33fe023b5f3eff316b0d5b6b5fae3dd876da9c13eaf645cc7beaeeee447383f1cb3dd75d6df65da69cba0bd9797591e011844787788502971a1'
```

---

# 4

## Description

In this challenge you will complete an RSA challenge-response. You will provide the public key.

## Solution

We can generate our own key:

```python
>>> from sympy import isprime, primerange, randprime

>>> q = randprime(2**300, 2**500)
>>> p = randprime(2**300, 2**500)
>>> n = p * q
>>> n.to_bytes(256, "big").hex()
'000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003592aeecb167c27202d90625c99b3c21d15b8a2bc72d288360d986cbc2f53a663c491d5ac37408527efadf22588f4e2a1b192017d471e86fdadd299abd620aea9c44296a198e3a26784c1f4ab23305a68712801bad4b3117c21d57ce305c7a83a749eff95a782da47037f06da45067e21d98028ccfb7061be2c74fad7'
>>> e = randprime(2**10, 2**20)
>>> phi_n = (p - 1) * (q - 1)
>>> d = pow(e, -1, phi_n)
>>> e.to_bytes(256, "big").hex()
'000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a7f15'

>>> c = bytes.fromhex("791982d989494b4ae792e62f4e20318bbcffb6f1067da7f32ff56f010690f361ee6e338a44594e05ec76e20e3eb4ac15faccdb8492bb8f564481b0d3fcabd434")
>>> pow(int.from_bytes(c, "big"), d, n).to_bytes(256, "big").hex()
'0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011d0d046646160794fba8e9143b4d77b901d8bb43e01529e1fffbddc10a83d0d062f2b72f2024926cf0c5138dc08dc047a1af6c6b9a542a169707e15b60d003fd34c9ca3e5488355de97fce88d9aa277c468a810f22a5b22c3bcf73f4d63870f914770879b1cc5864a73f97778448141f89b7bba46d3f62afa8a64c71'

>>> secret = bytes.fromhex("zDEp3rLcArWB716d7UzvNNH5qVH5RhKyWE1ojIako7cKO+eYiWUsLBfRRT1aaJbz2soRFKlyDrDihBHxdd/L4OyGkxvCd+TgVBkDfF8rNAxaMPyffNQwVbEY6nLIrqu1Y4H45U43nbnYlqLa5oimzipH1FPxcQlru/N3pQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

>>> import base64

>>> secret = base64.b64decode("zDEp3rLcArWB716d7UzvNNH5qVH5RhKyWE1ojIako7cKO+eYiWUsLBfRRT1aaJbz2soRFKlyDrDihBHxdd/L4OyGkxvCd+TgVBkDfF8rNAxaMPyffNQwVbEY6nLIrqu1Y4H45U43nbnYlqLa5oimzipH1FPxcQlru/N3pQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
>>> secret
b'\xcc1)\xde\xb2\xdc\x02\xb5\x81\xef^\x9d\xedL\xef4\xd1\xf9\xa9Q\xf9F\x12\xb2XMh\x8c\x86\xa4\xa3\xb7\n;\xe7\x98\x89e,,\x17\xd1E=Zh\x96\xf3\xda\xca\x11\x14\xa9r\x0e\xb0\xe2\x84\x11\xf1u\xdf\xcb\xe0\xec\x86\x93\x1b\xc2w\xe4\xe0T\x19\x03|_+4\x0cZ0\xfc\x9f|\xd40U\xb1\x18\xear\xc8\xae\xab\xb5c\x81\xf8\xe5N7\x9d\xb9\xd8\x96\xa2\xda\xe6\x88\xa6\xce*G\xd4S\xf1q\tk\xbb\xf3w\xa5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> secret_int = int.from_bytes(secret, "little")
>>> pow(secret_int, d, n).to_bytes(256, "little")
```

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
