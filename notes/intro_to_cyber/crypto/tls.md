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

---

# 2 

## Description

In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server. You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key. The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange. The server must complete the key exchange, and derive an AES-128 key from the exchanged secret. Then, using the encrypted channel, the server must supply the requested user certificate, signed by root. Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.

## Solution


