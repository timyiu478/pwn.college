---
tags: ["Reverse Engineering"]
title: "A Basic cIMG in Python"
description: A Basic cIMG in Python
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

It's time to upgrade to a new version of the cIMG, getting much closer to usurping the boring old image formats of the web. Spot what's different, understand what /challenge/cimg wants, and get the flag!

# Solution

## 1. read the python code

- data constains list of pixels
- each pixel contains 3 bytes to represent rgb and 1 byte ascii
- pixel is fixed: asu maroon

```python
#!/opt/pwn.college/python

import os
import sys
from collections import namedtuple

Pixel = namedtuple("Pixel", ["r", "g", "b", "ascii"])


def main():
    if len(sys.argv) >= 2:
        path = sys.argv[1]
        assert path.endswith(".cimg"), "ERROR: file has incorrect extension"
        file = open(path, "rb")
    else:
        file = sys.stdin.buffer

    header = file.read1(16)
    assert len(header) == 16, "ERROR: Failed to read header!"

    assert header[:4] == b"cIMG", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:8], "little") == 2, "ERROR: Invalid version!"

    width = int.from_bytes(header[8:12], "little")
    assert width == 20, "ERROR: Incorrect width!"

    height = int.from_bytes(header[12:16], "little")
    assert height == 22, "ERROR: Incorrect height!"

    data = file.read1(width * height * 4)
    assert len(data) == width * height * 4, "ERROR: Failed to read data!"

    pixels = [Pixel(*data[i : i + 4]) for i in range(0, len(data), 4)]

    invalid_character = next((pixel.ascii for pixel in pixels if not (0x20 <= pixel.ascii <= 0x7E)), None)
    assert invalid_character is None, f"ERROR: Invalid character {invalid_character:#04x} in data!"

    ansii_escape = lambda pixel: f"\x1b[38;2;{pixel.r:03};{pixel.g:03};{pixel.b:03}m{chr(pixel.ascii)}\x1b[0m"
    framebuffer = "".join(
        "".join(ansii_escape(pixel) for pixel in pixels[row_start : row_start + width])
        + ansii_escape(Pixel(0, 0, 0, ord("\n")))
        for row_start in range(0, len(pixels), width)
    )
    print(framebuffer)

    nonspace_count = sum(1 for pixel in pixels if chr(pixel.ascii) != " ")
    if nonspace_count != 440:
        return

    asu_maroon = (0x8C, 0x1D, 0x40)
    if any((pixel.r, pixel.g, pixel.b) != asu_maroon for pixel in pixels):
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

## 2. create proper .cimg file

```python
     1	import struct
     2	
     3	with open("flag.cimg", "wb") as f:
     4	    magic = b"cIMG"
     5	    version = 2
     6	    version = version.to_bytes(4, "little")
     7	    width = 20
     8	    width = width.to_bytes(4, "little")
     9	    height = 22
    10	    height = height.to_bytes(4, "little")
    11	
    12	
    13	    f.write(magic)
    14	    f.write(version)
    15	    f.write(width)
    16	    f.write(height)
    17	
    18	    for i in range(20*22-440):
    19	       f.write(b"\x20\x20\x20\x20")
    20	    for i in range(440):
    21	       f.write(b"\x8c\x1d\x40\x30")
```

## 3. run cimg

```
hacker@reverse-engineering~a-basic-cimg-python:/challenge$ ./cimg ~/flag.cimg
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000
00000000000000000000

pwn.college{00ce82qe4ogFlC-dGO-rs6O_HrW.01NxUjNxwCM0YjMyEzW}
```
