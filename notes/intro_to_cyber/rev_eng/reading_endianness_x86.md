---
tags: ["Reverse Engineering", "Endianness"]
title: "Reading Endianness in x86"
description: Reading Endianness in x86
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to the [reading_endianness_python.md](reading_endianness_python.md), but in x86.

# Solution

## 1. disassemble the binary

main:

```
   0x00000000004012c8 <+132>:	lea    0xe29(%rip),%rcx        # 0x4020f8
   0x00000000004012cf <+139>:	call   0x4014fb <read_exact>
   0x00000000004012d4 <+144>:	cmpl   $0x366d6e7b,0x4(%rsp)
   0x00000000004012dc <+152>:	je     0x4012f2 <main+174>
   0x00000000004012de <+154>:	lea    0xe31(%rip),%rdi        # 0x402116
   0x00000000004012e5 <+161>:	call   0x401130 <puts@plt>
   0x00000000004012ea <+166>:	or     $0xffffffff,%edi
   0x00000000004012ed <+169>:	call   0x4011e0 <exit@plt>
```

the instruction that probably checks the magic number is:

```
0x00000000004012d4 <+144>:	cmpl   $0x366d6e7b,0x4(%rsp)
```

Magic number:

```
(gdb) print/s 0x366d6e7b
$1 = 913141371
```

## 2. Run cimg with the magic number

```
./cimg ~/flag.cimg 
pwn.college{YdKAfuxhKkb11KLRN8_-zIgYTDW.0VMwMDMxwCM0YjMyEzW}
```
