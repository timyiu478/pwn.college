---
tags: ["Reverse Engineering", "Version Information"]
title: "Version Information in Python"
description: Version Information in Python
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Programs that parse evolving file formats must be able to tell what version of the format it must parse. This is, often, stored right near the magic number. Figure out how to provide the right cIMG version to this /challenge/cimg!

Writing binary data: You will find that you need to create files with characters that you cannot type on a keyboard for this level. You can do this in a number of ways, but one of these ways is creating a Python script to craft this file for you:

First, open the file that you want to write.

```
with open("my-file", "wb") as out_file:
```

The "wb" above tells Python to open the "my-file" file for writing raw bytes. Once we have this, we can write to it. Of course, you are familiar with the typical writing of files:

```
with open("my-file", "wb") as out_file:
    out_file.write(b"HELLO WORLD")
```

As you can see, characters that you can type normally can just be put in the Python bytestring to send to the file. What about others? As you may have previously seen in Python bytestrings, you can specify characters by their raw byte value using the \x "escape sequence". For example, \x41 creates a byte with a hexidecimal value of 0x41, which is an ASCII A. First, let's use this to write the above in a different way:

```
with open("my-file", "wb") as out_file:
  out_file.write(b"HELLO \x57\x4f\x52\x4c\x44")
```

This also writes HELLO WORLD into the file! The escape sequences are parsed by Python when it creates the bytestring as it executes your code

You can use other values to craft otherwise-untypable characters. For example, here we insert a null byte (value 0) after HELLO WORLD:

```
with open("my-file", "wb") as out_file:
  out_file.write(b"HELLO \x57\x4f\x52\x4c\x44\x00")
```

Null bytes are used in a lot of binary formats and protocols, as are plenty of other bytes with hard-to-type values. For some common ones, there are other "escape sequences" you can use as shorthand. Here are a few examples:

```
assert b"\0" == b"\x00" # our null byte
assert b"\n" == b"\x0a" # a newline
```

You also need to "escape" characters that would, for example, interfere with Python's syntax itself. For example, this prints HELLO "WORLD"!:

```
with open("my-file", "wb") as out_file:
  out_file.write(b"HELLO \"WORLD\"!")
```

The double quotes above must be escaped so that Python doesn't interpret them as the end of the bytestring!

Writing integer values: Of course, some bytes in a file format represent integers, typically stored in little-endian format. Writing these will require you to "pack" a typical integer (e.g., 5) into its binary representation (this depends on the size of the variable. For example, a 32-bit/4-byte 1 would be b"\x05\x00\x00\x00).

To convert between integers and raw bytes, check out the struct Python package.

```
with open("my-file", "wb") as out_file:
  # this packs the integer 1337 (0x539 in hex) into four little-endian bytes
  out_file.write(struct.pack("<I", 1337))

  # the above is equivalent to
  out_file.write(b"\x39\x05\x00\x00")

  # this packs the integer 1337 (0x539 in hex) two little-endian bytes
  out_file.write(struct.pack("<H", 1337))

  # the above is equivalent to
  out_file.write(b"\x39\x05")
```

If you are curious, you can look at other format specifiers in struct's documentation.

# Solution

## 1. read the python script

Related code snippet:

```python
    header = file.read1(6)
    assert len(header) == 6, "ERROR: Failed to read header!"

    assert header[:4] == b"<0%r", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:6], "little") == 125, "ERROR: Invalid version!"
```

## 2. create a file with the magic number and version

```python
import struct

magic_num = b"<0%r"
version = 125
bin_version = struct.pack('<I', version)

with open("flag.cimg", "wb") as f:
    f.write(magic_num)
    f.write(bin_version)
```

## 3. run cimg

```
hacker@reverse-engineering~version-information-python:/challenge$ ./cimg ~/flag.cimg 
pwn.college{gOhU6vftpo3mJktcmHHe-2t6q76.0VOwUjNxwCM0YjMyEzW}
```
