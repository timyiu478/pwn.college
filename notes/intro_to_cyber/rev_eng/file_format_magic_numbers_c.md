---
tags: ["Reverse Engineering", "File Format", "Magic Number"]
title: "File Format: Magic Numbers in C"
description: Reverse engineering by checking the c program
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to the [file_format_magic_numbers_python.md](file_format_magic_numbers_python.md), but in C.

# Solution

## 1. cat the cimg.c

the magic number is b"(~m6"

```c
    if (cimg.header.magic_number[0] != '(' || cimg.header.magic_number[1] != '~' || cimg.header.magic_number[2] != 'm' || cimg.header.magic_number[3] != '6')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }
```

## 2. create a file with the magic number

```c
with open("flag.cimg", "wb") as f:
    f.write(b"(~m6")
```

## 3. run the cimg binary with the created file

```
hacker@reverse-engineering~file-formats-magic-numbers-c:/challenge$ ./cimg ~/f.cimg
pwn.college{A_xS7czytwGy5U9Z0zGJGsSl2Ut.0lNwUjNxwCM0YjMyEzW}
```
