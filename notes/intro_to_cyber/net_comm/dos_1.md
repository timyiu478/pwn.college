---
tags: ["Computer Networking"]
title: "Denied of Service 1"
description: Denied of Service 1
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

The client at 10.0.0.3 is communicating with the server at 10.0.0.2 on port 31337. Deny this service.

# Solution

Establish the tcp connection to the server.

```bash
nc 10.0.0.2 31337
```

This works because the server only can serve 1 connection at a time.
