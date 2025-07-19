---
tags: ["Computer Networking", "TCP"]
title: "TCP Handshake"
description: TCP Handshake
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

Manually perform a Transmission Control Protocol handshake. The initial packet should have TCP sport=31337, dport=31337, seq=31337. The handshake should occur with the remote host at 10.0.0.2.

# Solution

```python
     1	from scapy.all import IP, TCP, sr1, send
     2	
     3	ip = IP(src="10.0.0.1", dst="10.0.0.2")
     4	syn = TCP(sport=31337, dport=31337, flags="S", seq=31337)
     5	
     6	syn_ack = sr1(ip/syn) # send syn and wait syn+ack
     7	
     8	ack = TCP(sport=31337, dport=31337, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
     9	
    10	send(ip/ack) # send last ack
```
