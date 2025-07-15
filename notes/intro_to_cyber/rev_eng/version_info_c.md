---
tags: ["Reverse Engineering", "Version Information"]
title: "Version Information in C"
description: Version Information in C
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to the [version_info_python.md](version_info_python.md), but in C.

# Solution

## 1. Check the C code

header check code snippet:

```c
    if (cimg.header.magic_number[0] != '[' || cimg.header.magic_number[1] != 'l' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'g')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 225)
```

## 2. create a file with the magic number and version

```python
import struct


magic_num = b"[lMg"
version = 225
bin_version = struct.pack('<I', version)

with open("flag.cimg", "wb") as f:
    f.write(magic_num)
    f.write(bin_version)
```

## 3. run cimg

```
hacker@reverse-engineering~version-information-python:/challenge$ ./cimg ~/flag.cimg 
pwn.college{46akIIKOYc0QdgSHEuXZ1cjDOFN.0FMxUjNxwCM0YjMyEzW}
```
