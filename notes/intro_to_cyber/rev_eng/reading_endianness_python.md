---
tags: ["Reverse Engineering", "Endianness"]
title: "Reading Endianness in Python"
description: Reading Endianness in Python
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Related to [file_format_magic_numbers_python.md](file_format_magic_numbers_python.md).

The most expedient way for computers to verify a magic number is by treating it as, well, a number. That's what this challenge's /challenge/cimg does, to show you how these things are typically done in practice. Here, we have a different magic number (otherwise there'd be no need to reverse the binary!) from the previous challenge. Reverse the binary, keep endianness in mind, and pass the magic number check for the flag.

# Solution

## 1. check the python script

The magic number is `0x527E6E63`, which is the ASCII representation of `cimg~R`. The script reads the first 4 bytes of the file and checks if it matches this magic number in little-endian format.

```python
hacker@reverse-engineering~reading-endianness-python:/challenge$ cat cimg 
#!/opt/pwn.college/python

import os
import sys
from collections import namedtuple

Pixel = namedtuple("Pixel", ["ascii"])


def main():
    if len(sys.argv) >= 2:
        path = sys.argv[1]
        assert path.endswith(".cimg"), "ERROR: file has incorrect extension"
        file = open(path, "rb")
    else:
        file = sys.stdin.buffer

    header = file.read1(4)
    assert len(header) == 4, "ERROR: Failed to read header!"

    assert int.from_bytes(header[:4], "little") == 0x527E6E63, "ERROR: Invalid magic number!"

    with open("/flag", "r") as f:
        flag = f.read()
        print(flag)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(e, file=sys.stderr)
        sys.exit(-1)
```

## 2. Write the magic number in litte-endian format in flag.cimg

```python
import struct

data = 0x527E6E63
bin_data = struct.pack('<I', data)

with open("flag.cimg", "wb") as f:
    f.write(bin_data)
```

## 3. Run the cimg binary

```
./cimg ~/flag.cimg 
pwn.college{wumHZjv8fRbUOBGs13ZMGcaYVPU.01NwUjNxwCM0YjMyEzW}
```
