---
tags: ["Reverse Engineering"]
title: "Behold the cIMG! x86"
description: Behold the cIMG! x86
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to [behold_the_cimg_python.md](behold_the_cimg_python.md), but in x86.

# Solution

## 1. Disassemble the binary

main function:

```
Dump of assembler code for function main:
   0x0000000000401284 <+0>:	endbr64
   0x0000000000401288 <+4>:	push   %r12
   0x000000000040128a <+6>:	mov    %edi,%r8d
   0x000000000040128d <+9>:	mov    $0x7,%ecx
   0x0000000000401292 <+14>:	push   %rbp
   0x0000000000401293 <+15>:	push   %rbx
   0x0000000000401294 <+16>:	sub    $0x30,%rsp
   0x0000000000401298 <+20>:	mov    %fs:0x28,%rax
   0x00000000004012a1 <+29>:	mov    %rax,0x28(%rsp)
   0x00000000004012a6 <+34>:	xor    %eax,%eax
   0x00000000004012a8 <+36>:	lea    0xc(%rsp),%rdi
   0x00000000004012ad <+41>:	dec    %r8d
   0x00000000004012b0 <+44>:	lea    0xc(%rsp),%rbp
   0x00000000004012b5 <+49>:	rep stos %eax,%es:(%rdi)
   0x00000000004012b7 <+51>:	jle    0x401308 <main+132>
   0x00000000004012b9 <+53>:	mov    0x8(%rsi),%r12
   0x00000000004012bd <+57>:	or     $0xffffffffffffffff,%rcx
   0x00000000004012c1 <+61>:	lea    0xe0b(%rip),%rsi        # 0x4020d3
   0x00000000004012c8 <+68>:	mov    %r12,%rdi
   0x00000000004012cb <+71>:	repnz scas %es:(%rdi),%al
   0x00000000004012cd <+73>:	not    %rcx
   0x00000000004012d0 <+76>:	lea    -0x6(%r12,%rcx,1),%rdi
   0x00000000004012d5 <+81>:	call   0x4011d0 <strcmp@plt>
   0x00000000004012da <+86>:	test   %eax,%eax
   0x00000000004012dc <+88>:	je     0x4012f3 <main+111>
   0x00000000004012de <+90>:	lea    0xdf4(%rip),%rsi        # 0x4020d9
   0x00000000004012e5 <+97>:	mov    $0x1,%edi
   0x00000000004012ea <+102>:	xor    %eax,%eax
   0x00000000004012ec <+104>:	call   0x4011f0 <__printf_chk@plt>
   0x00000000004012f1 <+109>:	jmp    0x40134a <main+198>
   0x00000000004012f3 <+111>:	xor    %esi,%esi
   0x00000000004012f5 <+113>:	mov    %r12,%rdi
   0x00000000004012f8 <+116>:	xor    %eax,%eax
   0x00000000004012fa <+118>:	call   0x401210 <open@plt>
   0x00000000004012ff <+123>:	xor    %esi,%esi
   0x0000000000401301 <+125>:	mov    %eax,%edi
   0x0000000000401303 <+127>:	call   0x401190 <dup2@plt>
   0x0000000000401308 <+132>:	or     $0xffffffff,%r8d
   0x000000000040130c <+136>:	xor    %edi,%edi
   0x000000000040130e <+138>:	lea    0xde3(%rip),%rcx        # 0x4020f8
   0x0000000000401315 <+145>:	mov    %rbp,%rsi
   0x0000000000401318 <+148>:	mov    $0x1c,%edx # 28 bytes header
   0x000000000040131d <+153>:	call   0x40161b <read_exact>
   0x0000000000401322 <+158>:	cmpb   $0x63,0xc(%rsp)
   0x0000000000401327 <+163>:	jne    0x40133e <main+186>
   0x0000000000401329 <+165>:	cmpb   $0x49,0xd(%rsp)
   0x000000000040132e <+170>:	jne    0x40133e <main+186>
   0x0000000000401330 <+172>:	cmpb   $0x4d,0xe(%rsp)
   0x0000000000401335 <+177>:	jne    0x40133e <main+186>
   0x0000000000401337 <+179>:	cmpb   $0x47,0xf(%rsp)
   0x000000000040133c <+184>:	je     0x401352 <main+206>
   0x000000000040133e <+186>:	lea    0xdd1(%rip),%rdi        # 0x402116
   0x0000000000401345 <+193>:	call   0x401160 <puts@plt>
   0x000000000040134a <+198>:	or     $0xffffffff,%edi
   0x000000000040134d <+201>:	call   0x401220 <exit@plt>
   0x0000000000401352 <+206>:	cmpq   $0x1,0x10(%rsp)
   0x0000000000401358 <+212>:	lea    0xdd4(%rip),%rdi        # 0x402133
   0x000000000040135f <+219>:	jne    0x401345 <main+193>
   0x0000000000401361 <+221>:	mov    0x18(%rsp),%r12 # width
   0x0000000000401366 <+226>:	imul   0x20(%rsp),%r12 # height
   0x000000000040136c <+232>:	mov    %r12,%rdi
   0x000000000040136f <+235>:	call   0x4011e0 <malloc@plt>
   0x0000000000401374 <+240>:	lea    0xdd4(%rip),%rdi        # 0x40214f
   0x000000000040137b <+247>:	mov    %rax,%rbx
   0x000000000040137e <+250>:	test   %rax,%rax
   0x0000000000401381 <+253>:	je     0x401345 <main+193>
   0x0000000000401383 <+255>:	mov    %r12d,%edx
   0x0000000000401386 <+258>:	mov    %rax,%rsi
   0x0000000000401389 <+261>:	or     $0xffffffff,%r8d
   0x000000000040138d <+265>:	xor    %edi,%edi
   0x000000000040138f <+267>:	lea    0xdee(%rip),%rcx        # 0x402184
   0x0000000000401396 <+274>:	call   0x40161b <read_exact>
   0x000000000040139b <+279>:	mov    0x18(%rsp),%rdx
   0x00000000004013a0 <+284>:	imul   0x20(%rsp),%rdx
   0x00000000004013a6 <+290>:	xor    %eax,%eax
   0x00000000004013a8 <+292>:	cmp    %rax,%rdx
   0x00000000004013ab <+295>:	je     0x4013dc <main+344>
   0x00000000004013ad <+297>:	movzbl (%rbx,%rax,1),%ecx
   0x00000000004013b1 <+301>:	inc    %rax
   0x00000000004013b4 <+304>:	lea    -0x20(%rcx),%esi
   0x00000000004013b7 <+307>:	cmp    $0x5e,%sil
   0x00000000004013bb <+311>:	jbe    0x4013a8 <main+292>
   0x00000000004013bd <+313>:	mov    0x2c7c(%rip),%rdi        # 0x404040 <stderr@@GLIBC_2.2.5>
   0x00000000004013c4 <+320>:	lea    0xdd5(%rip),%rdx        # 0x4021a0
   0x00000000004013cb <+327>:	mov    $0x1,%esi
   0x00000000004013d0 <+332>:	xor    %eax,%eax
   0x00000000004013d2 <+334>:	call   0x401230 <__fprintf_chk@plt>
   0x00000000004013d7 <+339>:	jmp    0x40134a <main+198>
   0x00000000004013dc <+344>:	mov    %rbx,%rsi
   0x00000000004013df <+347>:	mov    %rbp,%rdi
   0x00000000004013e2 <+350>:	call   0x40166b <display>
   0x00000000004013e7 <+355>:	mov    0x18(%rsp),%rcx
   0x00000000004013ec <+360>:	xor    %eax,%eax
   0x00000000004013ee <+362>:	xor    %edx,%edx
   0x00000000004013f0 <+364>:	imul   0x20(%rsp),%rcx
   0x00000000004013f6 <+370>:	cmp    %rax,%rcx
   0x00000000004013f9 <+373>:	je     0x401408 <main+388>
   0x00000000004013fb <+375>:	cmpb   $0x20,(%rbx,%rax,1)
   0x00000000004013ff <+379>:	je     0x401403 <main+383>
   0x0000000000401401 <+381>:	inc    %edx
   0x0000000000401403 <+383>:	inc    %rax
   0x0000000000401406 <+386>:	jmp    0x4013f6 <main+370>
   0x0000000000401408 <+388>:	cmp    $0x113,%edx
   0x000000000040140e <+394>:	jne    0x401417 <main+403>
   0x0000000000401410 <+396>:	xor    %eax,%eax
   0x0000000000401412 <+398>:	call   0x401526 <win>
   0x0000000000401417 <+403>:	mov    0x28(%rsp),%rax
   0x000000000040141c <+408>:	xor    %fs:0x28,%rax
   0x0000000000401425 <+417>:	je     0x40142c <main+424>
   0x0000000000401427 <+419>:	call   0x401180 <__stack_chk_fail@plt>
   0x000000000040142c <+424>:	add    $0x30,%rsp
   0x0000000000401430 <+428>:	xor    %eax,%eax
   0x0000000000401432 <+430>:	pop    %rbx
   0x0000000000401433 <+431>:	pop    %rbp
   0x0000000000401434 <+432>:	pop    %r12
   0x0000000000401436 <+434>:	ret
End of assembler dump.
```

Guess these about width and height:

```
   0x0000000000401361 <+221>:	mov    0x18(%rsp),%r12 # width
   0x0000000000401366 <+226>:	imul   0x20(%rsp),%r12 # height
```

Loop:

- `cmpb   $0x20,(%rbx,%rax,1)`: compare with space character
- `cmp    $0x113,%edx`: we want `0x113`(275) number of non-space characters

```
   0x00000000004013f6 <+370>:	cmp    %rax,%rcx
   0x00000000004013f9 <+373>:	je     0x401408 <main+388>
   0x00000000004013fb <+375>:	cmpb   $0x20,(%rbx,%rax,1)
   0x00000000004013ff <+379>:	je     0x401403 <main+383> # skip <main+381> -> $edx increase for each non-space
   0x0000000000401401 <+381>:	inc    %edx
   0x0000000000401403 <+383>:	inc    %rax
   0x0000000000401406 <+386>:	jmp    0x4013f6 <main+370>
   0x0000000000401408 <+388>:	cmp    $0x113,%edx
   0x000000000040140e <+394>:	jne    0x401417 <main+403>
   0x0000000000401410 <+396>:	xor    %eax,%eax
   0x0000000000401412 <+398>:	call   0x401526 <win>
   0x0000000000401417 <+403>:	mov    0x28(%rsp),%rax
```

## 2. create proper .cimg file

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"\x63\x49\x4d\x47"
    version = 1
    version = version.to_bytes(8, "little")
    width = struct.pack('<Q', 17)
    height = struct.pack('<Q', 17) # derived from header total is 0x28 bytes

    arr = [95 for _ in range(17*17)]

    for i in range(17*17-275):
        arr[i] = 32

    data = bytes(arr)

    f.write(magic)
    f.write(version)
    f.write(width)
    f.write(height)
    f.write(data)
```

## 3. run binary

```
hacker@reverse-engineering~behold-the-cimg-x86:/challenge$ ./cimg ~/flag.cimg
              ___
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
_________________
pwn.college{AgiXPk-ueQkdWGXrfuPi6ExmX0S.0VNwMDMxwCM0YjMyEzW}
```
