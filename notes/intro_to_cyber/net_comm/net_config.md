---
tags: ["Computer Networking"]
title: "Network Configuration"
description: Network Configuration
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

Configure your network interface. The remote host at 10.0.0.2 is trying to communicate with the remote host at 10.0.0.3 on port 31337.

# Solution

1. add ip `10.0.0.3` to device `eth0`

```
root@ip-10-0-0-1:/challenge# ip addr add 10.0.0.3/24 dev eth0
```

2. listen on 10.0.0.4 port 31337 for getting the data

```
root@ip-10-0-0-1:/challenge# nc -l 10.0.0.3 31337
pwn.college{QErmW_b_b3_D7_w3POPzQGrnM5p.QX1YzMzwCM0YjMyEzW}
```
