---
tags: ["Reverse Engineering", "Metadata"]
title: "Input Representation in Python"
description: Input Representation in Python
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Some programs impose specific constraints on their inputs. Keep building your knowledge of the cIMG format, but be aware of the restrictions that /challenge/cimg places on the additional data you have to send in this level.

# Solution

## 1. check the python program

Pixel constraints: 0x20 <= pixel.ascii <= 0x7E

```python
def main():
    if len(sys.argv) >= 2:
        path = sys.argv[1]
        assert path.endswith(".cimg"), "ERROR: file has incorrect extension"
        file = open(path, "rb")
    else:
        file = sys.stdin.buffer

    header = file.read1(11)
    assert len(header) == 11, "ERROR: Failed to read header!"

    assert header[:4] == b"cIMG", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:6], "little") == 1, "ERROR: Invalid version!"

    width = int.from_bytes(header[6:10], "little")
    assert width == 62, "ERROR: Incorrect width!"

    height = int.from_bytes(header[10:11], "little")
    assert height == 23, "ERROR: Incorrect height!"

    data = file.read1(width * height)
    assert len(data) == width * height, "ERROR: Failed to read data!"

    pixels = [Pixel(character) for character in data]

    invalid_character = next((pixel.ascii for pixel in pixels if not (0x20 <= pixel.ascii <= 0x7E)), None)
    assert invalid_character is None, f"ERROR: Invalid character {invalid_character:#04x} in data!"

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

## 2. create a proper cimg file based on (1)

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"cIMG"
    version = 1
    version = version.to_bytes(2, "little")
    width = b"\x3e\x00\x00\x00"
    height = b"\x17"

    data = bytes([33 for _ in range(62*23)])

    f.write(magic)
    f.write(version)
    f.write(width)
    f.write(height)
    f.write(data)
```

## 3. run cimg

```
hacker@reverse-engineering~input-restrictions-python:/challenge$ ./cimg ~/flag.cimg
pwn.college{gaTCI6_FngGYNEjsLJK5saDh3iZ.01MxUjNxwCM0YjMyEzW}
```
