---
tags: ["Reverse Engineering", "Metadata"]
title: "Metadata and Data in Python"
description: Metadata and Data in Python
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Let's continue building out the cIMG format. What does an image need? Dimensions! Specify the correct ones here, and grab your flag!

# Solution

## 1. Check the Python code

```python
def main():
    if len(sys.argv) >= 2:
        path = sys.argv[1]
        assert path.endswith(".cimg"), "ERROR: file has incorrect extension"
        file = open(path, "rb")
    else:
        file = sys.stdin.buffer

    header = file.read1(17)
    assert len(header) == 17, "ERROR: Failed to read header!"

    assert header[:4] == b"Clmg", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:5], "little") == 1, "ERROR: Invalid version!"

    width = int.from_bytes(header[5:9], "little")
    assert width == 71, "ERROR: Incorrect width!"

    height = int.from_bytes(header[9:17], "little")
    assert height == 21, "ERROR: Incorrect height!"

    data = file.read1(width * height)
    assert len(data) == width * height, "ERROR: Failed to read data!"

    pixels = [Pixel(character) for character in data]

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

### 2. Create a file with the correct header and data

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"Clmg"
    version = 1
    version = version.to_bytes(1, "little")
    width = 71
    bwidth = width.to_bytes(4, "little")
    height = 21
    bheight = height.to_bytes(8, "little")
    data = bytes([1 for _ in range(width*height)])

    f.write(magic)
    f.write(version)
    f.write(bwidth)
    f.write(bheight)
    f.write(data)
```

### 3. run cimg with correct header and data 

```
hacker@reverse-engineering~metadata-and-data-python:/challenge$ ./cimg ~/flag.cimg 
pwn.college{wRHkFEBp-kzXQlb5HZynVU1bewO.0VMxUjNxwCM0YjMyEzW}
```
