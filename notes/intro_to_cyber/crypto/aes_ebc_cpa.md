---
tags: ["Cryptography", "AES", "Block Cipher", "Chosen Plaintext Attack"]
title: "AES ECB Chosen Plaintext Attacks"
description: AES ECB Chosen Plaintext Attacks
reference: https://pwn.college/intro-to-cybersecurity/cryptography/
---

# AES ECB CPA

## Description

Though the core of the AES crypto algorithm is thought to be secure (not proven to be, though: no one has managed to do that! But no one has managed to significantly break the crypto in the 20+ years of its use, either), this core only encrypts 128-bit (16 byte) blocks at a time. To actually use AES in practice, one must build a cryptosystem on top of it.

In the previous level, we used the AES-ECB cryptosystem: an Electronic Codebook Cipher where every block is independently encrypted by the same key. This system is quite simple but, as we will discover here, extremely susceptible to a certain class of attack.

Cryptosystems are held to very high standard of ciphertext indistinguishability. That is, an attacker that lacks the key to the cryptosystem should not be able to distinguish between pairs of ciphertext based on the plaintext that was encrypted. For example, if the attacker looks at ciphertexts UVSDFGIWEHFBFFCA and LKXBFVYASLJDEWEU, and is able to determine that the latter was produced from the plaintext EEEEFFFFGGGGHHHH (or, in fact, figure out any information about the plaintext at all!), the cryptosystem is considered broken. This property must hold even if the attacker already knows part or all of the plaintext, a setting known as the Known Plaintext Attack, or can even control part or all of the plaintext, a setting known as the Chosen Plaintext Attack!

ECB is susceptible to both known and chosen plaintext attack. Because every block is encrypted with the same key, with no other modifications, an attacker can observe identical ciphertext across different blocks that have identical plaintext. Moreover, if the attacker can choose or learn the plaintext associated with some of these blocks, they can carefully build a mapping from known-plaintext to known-ciphertext, and use that as a lookup table to decrypt other matching ciphertext!

In this level, you will do just this: you will build a codebook mapping from ciphertext to chosen plaintext, then use that to decrypt the flag. Good luck!

HINT: You might find it helpful to automate interactions with this challenge. You can do so using the pwntools Python package. Check out this pwntools cheatsheet from a fellow pwn.college student!

## Solution

The idea is similar with [SQL injection Level 5 script](notes/intro_to_cyber/web_sec/sqli.md#5) which is guessing the flag byte by byte.

```python
1	from pwn import *
2	import string
3	
4	p = process("/challenge/run")
5	
6	flag = ""
7	idx = 0
8	
9	while True:
10	    for c in string.printable:
11	        p.readuntil("Choice? ")
12	        p.write("2\n")
13	        p.readuntil("Index? ")
14	        p.write(str(idx)+"\n")
15	        p.readuntil("Length? ")
16	        p.write("1\n")
17	        p.readuntil('Result: ')
18	        cipher1 = p.readline()
19	        p.readuntil("Choice? ")
20	        p.write("1\n")
21	        p.readuntil("Data? ")
22	        p.write(f"{c}\n")
23	        p.readuntil('Result: ')
24	        cipher2 = p.readline()
25	        if cipher1 == cipher2:
26	            flag += c
27	            idx += 1
28	            print(flag)
29	            break
```
---

# AES ECB CPA HTTP

## Description

Okay, now we'll try that attack in a slightly more realistic scenario. Can you remember your SQL to carry out the attack and recover the flag?

HINT: Remember that you can make select return chosen plaintext by doing SELECT 'my_plaintext'!

## Solution



---

# AES ECB CPA (base64)

## Description

For historical reasons, different encodings tend to gain traction in different contexts. For example, on the web, the standard way to encode binary data is base64, an encoding that you learned in Dealing with Data. Channel this skill now, adapting your previous solution for base64!

You'll (re-)note that base64 isn't as convenient to reason about as hex. Why do people use it? One reason: every byte requires two hex letters to encode, whereas base64 encodes every 3 bytes with 4 letters. This means that, when sending each letter as a byte itself over the network, for example, base64 is marginally more efficient. On the other hand, it's a headache to work with, because of the unclean bit boundaries!

Throughout the rest of the modules, challenges might use hex or base64, as our heart desires. It's important to be able to handle either!

## Solution

---

# AES ECB CPA Suffix

## Description

Okay, now let's complicate things slightly to increase the realism. It's rare that you can just craft queries for the plaintext that you want. However, it's less rare that you can isolate the tail end of some data into its own block, and in ECB, this is bad news. We'll explore this concept in this challenge, replacing your ability to query substrings of the flag with just an ability to encrypt some bytes off the end.

Show us that you can still solve this!

HINT: Keep in mind that, once you recover some part of the end of the flag, you can build a new codebook with additional prefixes of the known parts, and repeat the attack on the previous byte!

## Solution

---

# AES ECB CPA Prefix

## Description

Okay, now let's complicate things slightly. It's not so common that you can just chop off the end of interesting data and go wild. However, much more common is the ability to prepend chosen plaintext to a secret before it's encrypted. If you carefully craft the prepended data so that it pushes the end of the secret into a new block, you've just successfully isolated it, accomplishing the same as if you were chopping it off!

Go ahead and do that in this challenge. The core attack is the same as before, it just involves more data massaging.

HINT: Keep in mind that a typical pwn.college flag is somewhere upwards of 50 bytes long. This is four blocks (three full and one partial), and the length can vary slightly. You will need to experiment with how many bytes you must prepend to push even one of the end characters to its own block.

HINT: Keep in mind that blocks are 16 bytes long! After you leak the last 16 bytes, you'll be looking at the second-to-last block, and so on.

## Solution

---

# AES ECB CPA Prefix 2

## Description

The previous challenge ignored something very important: padding. AES has a 128-bit (16 byte) block size. This means that input to the algorithm must be 16 bytes long, and any input shorter than that must be padded to 16 bytes by having data added to the plaintext before encryption. When the ciphertext is decrypted, the result must be unpadded (e.g., the added padding bytes must be removed) to recover the original plaintext.

How to pad is an interesting question. For example, you could pad with null bytes (0x00). But what if your data has null bytes at the end? They might be erroneously removed during unpadding, leaving you with a plaintext different than your original! This would not be good.

One padding standard (and likely the most popular) is PKCS7, which simply pads the input with bytes all containing a value equal to the number of bytes padded. If one byte is added to a 15-byte input, it contains the value 0x01, two bytes added to a 14-byte input would be 0x02 0x02, and the 15 bytes added to a 1-byte input would all have a value 0x0f. During unpadding, PKCS7 looks at the value of the last byte of the block and removes that many bytes. Simple!

But wait... What if exactly 16 bytes of plaintext are encrypted (e.g., no padding needed), but the plaintext byte has a value of 0x01? Left to its own devices, PKCS7 would chop off that byte during unpadding, leaving us with a corrupted plaintext. The solution to this is slightly silly: if the last block of the plaintext is exactly 16 bytes, we add a block of all padding (e.g., 16 padding bytes, each with a value of 0x10). PKCS7 removes the whole block during unpadding, and the sanctity of the plaintext is preserved at the expense of a bit more data.

Anyways, the previous challenge explicitly disabled this last case, which would have the result of popping in a "decoy" ciphertext block full of padding as you tried to push the very first suffix byte to its own block. This challenge pads properly. Watch out for that "decoy" block, and go solve it!

NOTE: The full-padding block will only appear when the last block of plaintext perfectly fills 16 bytes. It'll vanish when one more byte is appended (replaced with the padded new block containing the last byte of plaintext), but will reappear when the new block reaches 16 bytes in length.

## Solution

---

# AES ECB CPA Prefix Miniboss

## Description

This is the miniboss of AES-ECB-CPA. You don't get an easy way to build your codebook anymore: you must build it in the prefix. If you pad your own prefixed data yourself, you can control entire blocks, and that's all you need! Other than that, the attack remains the same. Good luck!

## Solution

---

# AES ECB CPA Prefix Boss

## Description

Okay, time for the AES-ECB-CPA final boss! Can you carry out this attack against an encrypted secret storage web server? Let's find out!

NOTE: Keep in mind that, unlike the previous levels, this level takes data in base64!

## Solution

