---
tags: ["Reverse Engineering", "Version Information"]
title: "Version Information in x86"
description: Version Information in x86
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to the [version_info_python.md](version_info_python.md), but in x86.

# Solution

## 1. Disassemble the binary

Code snippet between read() function and win() function:

```
0x00000000004012d7 <+147>:	call   0x40151b <read_exact>
   0x00000000004012dc <+152>:	cmpb   $0x28,0xc(%rsp)
   0x00000000004012e1 <+157>:	jne    0x4012f8 <main+180>
   0x00000000004012e3 <+159>:	cmpb   $0x4e,0xd(%rsp)
   0x00000000004012e8 <+164>:	jne    0x4012f8 <main+180>
   0x00000000004012ea <+166>:	cmpb   $0x6d,0xe(%rsp)
--Type <RET> for more, q to quit, c to continue without paging--
   0x00000000004012ef <+171>:	jne    0x4012f8 <main+180>
   0x00000000004012f1 <+173>:	cmpb   $0x67,0xf(%rsp)
   0x00000000004012f6 <+178>:	je     0x40130c <main+200>
   0x00000000004012f8 <+180>:	lea    0xe17(%rip),%rdi        # 0x402116
   0x00000000004012ff <+187>:	call   0x401130 <puts@plt>
   0x0000000000401304 <+192>:	or     $0xffffffff,%edi
   0x0000000000401307 <+195>:	call   0x4011e0 <exit@plt>
   0x000000000040130c <+200>:	cmpq   $0x74,0x10(%rsp)
   0x0000000000401312 <+206>:	lea    0xe1a(%rip),%rdi        # 0x402133
   0x0000000000401319 <+213>:	jne    0x4012ff <main+187>
   0x000000000040131b <+215>:	xor    %eax,%eax
   0x000000000040131d <+217>:	call   0x401426 <win>
```

version check using `cmpq`:

- this instruction compares two 64-bit (quadword) values instead of 32-bit.

```
0x000000000040130c <+200>:	cmpq   $0x74,0x10(%rsp)
```

read_exact function:

- <+25>: compare the number of bytes read with the expected number of bytes
- by dynamic analysis using gdb, we can see it expects to read 12 bytes

```
Dump of assembler code for function read_exact:
   0x000000000040151b <+0>:	endbr64
   0x000000000040151f <+4>:	push   %r12
   0x0000000000401521 <+6>:	movslq %edx,%rdx
   0x0000000000401524 <+9>:	mov    %rcx,%r12
   0x0000000000401527 <+12>:	push   %rbp
   0x0000000000401528 <+13>:	mov    %r8d,%ebp
   0x000000000040152b <+16>:	push   %rbx
   0x000000000040152c <+17>:	mov    %rdx,%rbx
   0x000000000040152f <+20>:	call   0x401190 <read@plt>
   0x0000000000401534 <+25>:	cmp    %eax,%ebx
   0x0000000000401536 <+27>:	je     0x401566 <read_exact+75>
   0x0000000000401538 <+29>:	mov    0x2b01(%rip),%rdi        # 0x404040 <stderr@@GLIBC_2.2.5>
   0x000000000040153f <+36>:	mov    %r12,%rdx
   0x0000000000401542 <+39>:	mov    $0x1,%esi
   0x0000000000401547 <+44>:	xor    %eax,%eax
   0x0000000000401549 <+46>:	call   0x4011f0 <__fprintf_chk@plt>
   0x000000000040154e <+51>:	mov    0x2aeb(%rip),%rsi        # 0x404040 <stderr@@GLIBC_2.2.5>
   0x0000000000401555 <+58>:	mov    $0xa,%edi
   0x000000000040155a <+63>:	call   0x401180 <fputc@plt>
   0x000000000040155f <+68>:	mov    %ebp,%edi
--Type <RET> for more, q to quit, c to continue without paging--
   0x0000000000401561 <+70>:	call   0x4011e0 <exit@plt>
   0x0000000000401566 <+75>:	pop    %rbx
   0x0000000000401567 <+76>:	pop    %rbp
   0x0000000000401568 <+77>:	pop    %r12
   0x000000000040156a <+79>:	ret
End of assembler dump.
```

check expected number of bytes read:

```
Breakpoint 6, 0x0000000000401534 in read_exact ()
(gdb) print $ebx
$18 = 12
```

## 2. create a file with the magic number and version

```python
import struct


with open("flag.cimg", "wb") as f:
    magic = b'\x28\x4e\x6d\x67'
    version = struct.pack('<q', 116)
    padding = b'\x01\x01\x28\x4e\x6d\x67\x74'
    f.write(magic)
    f.write(version)
    f.write(padding)
```

## 3. run cimg

```
hacker@reverse-engineering~version-information-x86:/challenge$ ./cimg ~/flag.cimg
pwn.college{U334AdgAXogwX6fuBTE09WxXQaL.0lMwMDMxwCM0YjMyEzW}
```
