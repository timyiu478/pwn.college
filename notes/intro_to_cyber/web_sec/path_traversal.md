---
tags: ["Web Security"]
title: "Path Traversal"
description: Denied of Service 1
reference: https://pwn.college/intro-to-cybersecurity/web-security/
---

# 1

## Description

This level will explore the intersection of Linux path resolution, when done naively, and unexpected web requests from an attacker. We've implemented a simple web server for you --- it will serve up files from /challenge/files over HTTP. Can you trick it into giving you the flag?

The webserver program is /challenge/server. You can run it just like any other challenge, then talk to it over HTTP (using a different terminal or a web browser). We recommend reading through its code to understand what it is doing and to find the weakness!

HINT: If you're wondering why your solution isn't working, make sure what you're trying to query is what is actually being received by the server! curl -v [url] can show you the exact bytes that curl is sending over.

---

# 2

## Description

The previous level's path traversal happened because of a disconnect between:

- The developer's awareness of the true range of potential input that an attacker might send to their application (e.g., the concept of an attacker sending characters that have special meaning in paths).
- A gap between the developer's intent (the implementation makes it clear that we only expect files under the /challenge/files directory to be served to the user) and the reality of the filesystem (where paths can go "back" up a directory level).

This level tries to stop you from traversing the path, but does it in a way that clearly demonstrates a further lack of the developer's understanding of how tricky paths can truly be. Can you still traverse it?
