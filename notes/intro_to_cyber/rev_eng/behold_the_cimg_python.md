---
tags: ["Reverse Engineering"]
title: "Behold the cIMG! Python"
description: Behold the cIMG! Python
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

It is time to look at your first cIMG! Make the program display an image with the correct properties, and it will give you the flag.

# Solution

## 1. read the python code

nonspace_count needs to be 275.

```python
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

    header = file.read1(15)
    assert len(header) == 15, "ERROR: Failed to read header!"

    assert header[:4] == b"cIMG", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:12], "little") == 1, "ERROR: Invalid version!"

    width = int.from_bytes(header[12:13], "little")

    height = int.from_bytes(header[13:15], "little")

    data = file.read1(width * height)
    assert len(data) == width * height, "ERROR: Failed to read data!"

    pixels = [Pixel(character) for character in data]

    invalid_character = next((pixel.ascii for pixel in pixels if not (0x20 <= pixel.ascii <= 0x7E)), None)
    assert invalid_character is None, f"ERROR: Invalid character {invalid_character:#04x} in data!"

    framebuffer = "".join(
        bytes(pixel.ascii for pixel in pixels[row_start : row_start + width]).decode() + "\n"
        for row_start in range(0, len(pixels), width)
    )
    print(framebuffer)

    nonspace_count = sum(1 for pixel in pixels if chr(pixel.ascii) != " ")
    if nonspace_count != 275:
        return

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

## 2. create a proper file based on (1)

```python
     1	import struct
     2	
     3	with open("flag.cimg", "wb") as f:
     4	    magic = b"cIMG"
     5	    version = 1
     6	    version = version.to_bytes(8, "little") # 0xc - 0x4 = 8 bytes
     7	    width = b"\x42"
     8	    height = b"\x11\x00"
     9	
    10	    arr = [95 for _ in range(66*17)]
    11	
    12	    for i in range(66*17-275): # keep the last 275 to non space characters
    13	        arr[i] = 32
    14	
    15	    data = bytes(arr)
    16	
    17	    f.write(magic)
    18	    f.write(version)
    19	    f.write(width)
    20	    f.write(height)
    21	    f.write(data)
```

## 3. run cimg

```
hacker@reverse-engineering~behold-the-cimg-python:/challenge$ ./cimg ~/flag.cimg












                                                       ___________
__________________________________________________________________
__________________________________________________________________
__________________________________________________________________
__________________________________________________________________

pwn.college{U5juXq6E2Y_jpiqWT5iKQqw2v6B.0VNxUjNxwCM0YjMyEzW}
```
