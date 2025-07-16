---
tags: ["Reverse Engineering", "Metadata"]
title: "Metadata and Data in x86"
description: Metadata and Data in x86
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to [meta_data_and_data_python.md](meta_data_and_data_python.md), but in x86.

# Solution

## 1. disassemble the binary

main function:

```
Dump of assembler code for function main:
   0x0000000000401264 <+0>:	endbr64
   0x0000000000401268 <+4>:	push   %rbp
   0x0000000000401269 <+5>:	mov    %edi,%r8d
   0x000000000040126c <+8>:	mov    $0x11,%ecx
   0x0000000000401271 <+13>:	sub    $0x20,%rsp
   0x0000000000401275 <+17>:	mov    %fs:0x28,%rax
   0x000000000040127e <+26>:	mov    %rax,0x18(%rsp)
   0x0000000000401283 <+31>:	xor    %eax,%eax
   0x0000000000401285 <+33>:	lea    0x7(%rsp),%rdi
   0x000000000040128a <+38>:	dec    %r8d
   0x000000000040128d <+41>:	rep stos %al,%es:(%rdi)
   0x000000000040128f <+43>:	jle    0x4012e0 <main+124>
   0x0000000000401291 <+45>:	mov    0x8(%rsi),%rbp
   0x0000000000401295 <+49>:	or     $0xffffffffffffffff,%rcx
   0x0000000000401299 <+53>:	lea    0xe33(%rip),%rsi        # 0x4020d3
   0x00000000004012a0 <+60>:	mov    %rbp,%rdi
   0x00000000004012a3 <+63>:	repnz scas %es:(%rdi),%al
   0x00000000004012a5 <+65>:	not    %rcx
   0x00000000004012a8 <+68>:	lea    -0x6(%rbp,%rcx,1),%rdi
   0x00000000004012ad <+73>:	call   0x4011b0 <strcmp@plt>
   0x00000000004012b2 <+78>:	test   %eax,%eax
   0x00000000004012b4 <+80>:	je     0x4012cb <main+103>
   0x00000000004012b6 <+82>:	lea    0xe1c(%rip),%rsi        # 0x4020d9
   0x00000000004012bd <+89>:	mov    $0x1,%edi
   0x00000000004012c2 <+94>:	xor    %eax,%eax
   0x00000000004012c4 <+96>:	call   0x4011d0 <__printf_chk@plt>
   0x00000000004012c9 <+101>:	jmp    0x401324 <main+192>
   0x00000000004012cb <+103>:	xor    %esi,%esi
   0x00000000004012cd <+105>:	mov    %rbp,%rdi
   0x00000000004012d0 <+108>:	xor    %eax,%eax
   0x00000000004012d2 <+110>:	call   0x4011f0 <open@plt>
   0x00000000004012d7 <+115>:	xor    %esi,%esi
   0x00000000004012d9 <+117>:	mov    %eax,%edi
   0x00000000004012db <+119>:	call   0x401170 <dup2@plt>
   0x00000000004012e0 <+124>:	or     $0xffffffff,%r8d
   0x00000000004012e4 <+128>:	xor    %edi,%edi
--Type <RET> for more, q to quit, c to continue without paging--
   0x00000000004012e6 <+130>:	lea    0x7(%rsp),%rsi
   0x00000000004012eb <+135>:	mov    $0x11,%edx
   0x00000000004012f0 <+140>:	lea    0xe01(%rip),%rcx        # 0x4020f8
   0x00000000004012f7 <+147>:	call   0x40158b <read_exact>
   0x00000000004012fc <+152>:	cmpb   $0x43,0x7(%rsp)
   0x0000000000401301 <+157>:	jne    0x401318 <main+180>
   0x0000000000401303 <+159>:	cmpb   $0x4e,0x8(%rsp)
   0x0000000000401308 <+164>:	jne    0x401318 <main+180>
   0x000000000040130a <+166>:	cmpb   $0x7e,0x9(%rsp)
   0x000000000040130f <+171>:	jne    0x401318 <main+180>
   0x0000000000401311 <+173>:	cmpb   $0x52,0xa(%rsp)
   0x0000000000401316 <+178>:	je     0x40132c <main+200>
   0x0000000000401318 <+180>:	lea    0xdf7(%rip),%rdi        # 0x402116
   0x000000000040131f <+187>:	call   0x401140 <puts@plt>
   0x0000000000401324 <+192>:	or     $0xffffffff,%edi
   0x0000000000401327 <+195>:	call   0x401200 <exit@plt>
   0x000000000040132c <+200>:	cmpb   $0x1,0xb(%rsp)
   0x0000000000401331 <+205>:	lea    0xdfb(%rip),%rdi        # 0x402133
   0x0000000000401338 <+212>:	jne    0x40131f <main+187>
   0x000000000040133a <+214>:	cmpl   $0x3d,0xc(%rsp)
   0x000000000040133f <+219>:	lea    0xe09(%rip),%rdi        # 0x40214f
   0x0000000000401346 <+226>:	jne    0x40131f <main+187>
   0x0000000000401348 <+228>:	cmpq   $0xf,0x10(%rsp)
   0x000000000040134e <+234>:	lea    0xe12(%rip),%rdi        # 0x402167
   0x0000000000401355 <+241>:	jne    0x40131f <main+187>
   0x0000000000401357 <+243>:	mov    $0x393,%edi
   0x000000000040135c <+248>:	call   0x4011c0 <malloc@plt>
   0x0000000000401361 <+253>:	lea    0xe18(%rip),%rdi        # 0x402180
   0x0000000000401368 <+260>:	mov    %rax,%rsi
   0x000000000040136b <+263>:	test   %rax,%rax
   0x000000000040136e <+266>:	je     0x40131f <main+187>
   0x0000000000401370 <+268>:	or     $0xffffffff,%r8d
   0x0000000000401374 <+272>:	xor    %edi,%edi
   0x0000000000401376 <+274>:	mov    $0x393,%edx
   0x000000000040137b <+279>:	lea    0xe33(%rip),%rcx        # 0x4021b5
   0x0000000000401382 <+286>:	call   0x40158b <read_exact>
   0x0000000000401387 <+291>:	xor    %eax,%eax
--Type <RET> for more, q to quit, c to continue without paging--c
   0x0000000000401389 <+293>:	call   0x401496 <win>
   0x000000000040138e <+298>:	mov    0x18(%rsp),%rax
   0x0000000000401393 <+303>:	xor    %fs:0x28,%rax
   0x000000000040139c <+312>:	je     0x4013a3 <main+319>
   0x000000000040139e <+314>:	call   0x401160 <__stack_chk_fail@plt>
   0x00000000004013a3 <+319>:	add    $0x20,%rsp
   0x00000000004013a7 <+323>:	xor    %eax,%eax
   0x00000000004013a9 <+325>:	pop    %rbp
   0x00000000004013aa <+326>:	ret
End of assembler dump.
```

- Assume 0xc(%rsp) is the width, 0x10(%rsp) is the height, then the size of width is 4 bytes.
- `cmpq` instruction is used to compare 64-bit values, so the height is also 8 bytes.

```
   0x000000000040133a <+214>:	cmpl   $0x3d,0xc(%rsp)
   0x000000000040133f <+219>:	lea    0xe09(%rip),%rdi        # 0x40214f
   0x0000000000401346 <+226>:	jne    0x40131f <main+187>
   0x0000000000401348 <+228>:	cmpq   $0xf,0x10(%rsp)
```

## 2. create a proper cimg file based on (1)

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"\x43\x4e\x7e\x52"
    version = 1
    version = version.to_bytes(1, "little")
    width = b"\x3d\x00\x00\x00"
    height = b"\x0f\x00\x00\x00\x00\x00\x00\x00"
    
    data = bytes([1 for _ in range(61*15)])

    f.write(magic)
    f.write(version)
    f.write(width)
    f.write(height)
    f.write(data)
```

## 3. run cimg

```
hacker@reverse-engineering~metadata-and-data-x86:/challenge$ ./cimg ~/flag.cimg
pwn.college{M3LVmZInvHhu3PSnYQmAks89pKl.01MwMDMxwCM0YjMyEzW}
```
