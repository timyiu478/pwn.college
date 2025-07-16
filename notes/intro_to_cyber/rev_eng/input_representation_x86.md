---
tags: ["Reverse Engineering", "Metadata"]
title: "Input Representation in x86"
description: Input Representation in x86
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to [input_representation_python.md](input_representation_python.md), but in x86.

# Solution

## 1. disassemble the binary

```
Dump of assembler code for function main:
   0x0000000000401264 <+0>:	endbr64
   0x0000000000401268 <+4>:	push   %rbp
   0x0000000000401269 <+5>:	xorps  %xmm0,%xmm0
   0x000000000040126c <+8>:	push   %rbx
   0x000000000040126d <+9>:	sub    $0x28,%rsp
   0x0000000000401271 <+13>:	mov    %fs:0x28,%rax
   0x000000000040127a <+22>:	mov    %rax,0x18(%rsp)
   0x000000000040127f <+27>:	xor    %eax,%eax
   0x0000000000401281 <+29>:	dec    %edi
   0x0000000000401283 <+31>:	movaps %xmm0,(%rsp)
   0x0000000000401287 <+35>:	jle    0x4012d8 <main+116>
   0x0000000000401289 <+37>:	mov    0x8(%rsi),%rbp
   0x000000000040128d <+41>:	or     $0xffffffffffffffff,%rcx
   0x0000000000401291 <+45>:	lea    0xe3b(%rip),%rsi        # 0x4020d3
   0x0000000000401298 <+52>:	mov    %rbp,%rdi
   0x000000000040129b <+55>:	repnz scas %es:(%rdi),%al
   0x000000000040129d <+57>:	not    %rcx
   0x00000000004012a0 <+60>:	lea    -0x6(%rbp,%rcx,1),%rdi
   0x00000000004012a5 <+65>:	call   0x4011b0 <strcmp@plt>
   0x00000000004012aa <+70>:	test   %eax,%eax
   0x00000000004012ac <+72>:	je     0x4012c3 <main+95>
   0x00000000004012ae <+74>:	lea    0xe24(%rip),%rsi        # 0x4020d9
   0x00000000004012b5 <+81>:	mov    $0x1,%edi
   0x00000000004012ba <+86>:	xor    %eax,%eax
   0x00000000004012bc <+88>:	call   0x4011d0 <__printf_chk@plt>
   0x00000000004012c1 <+93>:	jmp    0x401319 <main+181>
   0x00000000004012c3 <+95>:	xor    %esi,%esi
   0x00000000004012c5 <+97>:	mov    %rbp,%rdi
   0x00000000004012c8 <+100>:	xor    %eax,%eax
   0x00000000004012ca <+102>:	call   0x4011f0 <open@plt>
   0x00000000004012cf <+107>:	xor    %esi,%esi
   0x00000000004012d1 <+109>:	mov    %eax,%edi
   0x00000000004012d3 <+111>:	call   0x401170 <dup2@plt>
   0x00000000004012d8 <+116>:	or     $0xffffffff,%r8d
   0x00000000004012dc <+120>:	xor    %edi,%edi
   0x00000000004012de <+122>:	mov    %rsp,%rsi
   0x00000000004012e1 <+125>:	mov    $0x10,%edx
   0x00000000004012e6 <+130>:	lea    0xe0b(%rip),%rcx        # 0x4020f8
   0x00000000004012ed <+137>:	call   0x4015cb <read_exact>
   0x00000000004012f2 <+142>:	cmpb   $0x63,(%rsp)
   0x00000000004012f6 <+146>:	jne    0x40130d <main+169>
   0x00000000004012f8 <+148>:	cmpb   $0x49,0x1(%rsp)
   0x00000000004012fd <+153>:	jne    0x40130d <main+169>
   0x00000000004012ff <+155>:	cmpb   $0x4d,0x2(%rsp)
   0x0000000000401304 <+160>:	jne    0x40130d <main+169>
   0x0000000000401306 <+162>:	cmpb   $0x47,0x3(%rsp)
   0x000000000040130b <+167>:	je     0x401321 <main+189>
   0x000000000040130d <+169>:	lea    0xe02(%rip),%rdi        # 0x402116
   0x0000000000401314 <+176>:	call   0x401140 <puts@plt>
   0x0000000000401319 <+181>:	or     $0xffffffff,%edi
   0x000000000040131c <+184>:	call   0x401200 <exit@plt>
   0x0000000000401321 <+189>:	cmpq   $0x1,0x4(%rsp)
   0x0000000000401327 <+195>:	lea    0xe05(%rip),%rdi        # 0x402133
   0x000000000040132e <+202>:	jne    0x401314 <main+176>
   0x0000000000401330 <+204>:	cmpw   $0x42,0xc(%rsp)
   0x0000000000401336 <+210>:	lea    0xe12(%rip),%rdi        # 0x40214f
   0x000000000040133d <+217>:	jne    0x401314 <main+176>
   0x000000000040133f <+219>:	cmpw   $0x11,0xe(%rsp)
   0x0000000000401345 <+225>:	lea    0xe1b(%rip),%rdi        # 0x402167
   0x000000000040134c <+232>:	jne    0x401314 <main+176>
   0x000000000040134e <+234>:	mov    $0x462,%edi
   0x0000000000401353 <+239>:	call   0x4011c0 <malloc@plt>
   0x0000000000401358 <+244>:	lea    0xe21(%rip),%rdi        # 0x402180
   0x000000000040135f <+251>:	mov    %rax,%rbx
   0x0000000000401362 <+254>:	test   %rax,%rax
   0x0000000000401365 <+257>:	je     0x401314 <main+176>
   0x0000000000401367 <+259>:	mov    $0x462,%edx
   0x000000000040136c <+264>:	mov    %rax,%rsi
   0x000000000040136f <+267>:	or     $0xffffffff,%r8d
   0x0000000000401373 <+271>:	xor    %edi,%edi
   0x0000000000401375 <+273>:	lea    0xe39(%rip),%rcx        # 0x4021b5
   0x000000000040137c <+280>:	call   0x4015cb <read_exact>
   0x0000000000401381 <+285>:	movzwl 0xe(%rsp),%eax
   0x0000000000401386 <+290>:	movzwl 0xc(%rsp),%edx
   0x000000000040138b <+295>:	imul   %eax,%edx
--Type <RET> for more, q to quit, c to continue without paging--
   0x000000000040138e <+298>:	xor    %eax,%eax
   0x0000000000401390 <+300>:	cmp    %eax,%edx
   0x0000000000401392 <+302>:	jle    0x4013c3 <main+351>
   0x0000000000401394 <+304>:	movzbl (%rbx,%rax,1),%ecx
   0x0000000000401398 <+308>:	inc    %rax
   0x000000000040139b <+311>:	lea    -0x20(%rcx),%esi
   0x000000000040139e <+314>:	cmp    $0x5e,%sil
   0x00000000004013a2 <+318>:	jbe    0x401390 <main+300>
   0x00000000004013a4 <+320>:	mov    0x2c95(%rip),%rdi        # 0x404040 <stderr@@GLIBC_2.2.5>
   0x00000000004013ab <+327>:	lea    0xe1f(%rip),%rdx        # 0x4021d1
   0x00000000004013b2 <+334>:	mov    $0x1,%esi
   0x00000000004013b7 <+339>:	xor    %eax,%eax
   0x00000000004013b9 <+341>:	call   0x401210 <__fprintf_chk@plt>
   0x00000000004013be <+346>:	jmp    0x401319 <main+181>
   0x00000000004013c3 <+351>:	xor    %eax,%eax
   0x00000000004013c5 <+353>:	call   0x4014d6 <win>
   0x00000000004013ca <+358>:	mov    0x18(%rsp),%rax
   0x00000000004013cf <+363>:	xor    %fs:0x28,%rax
   0x00000000004013d8 <+372>:	je     0x4013df <main+379>
   0x00000000004013da <+374>:	call   0x401160 <__stack_chk_fail@plt>
   0x00000000004013df <+379>:	add    $0x28,%rsp
   0x00000000004013e3 <+383>:	xor    %eax,%eax
   0x00000000004013e5 <+385>:	pop    %rbx
   0x00000000004013e6 <+386>:	pop    %rbp
   0x00000000004013e7 <+387>:	ret
End of assembler dump.
```

- jbe (unsigned): jump to <main+300> if below or equal (0x5e) = 94

```
   0x000000000040139e <+314>:	cmp    $0x5e,%sil
   0x00000000004013a2 <+318>:	jbe    0x401390 <main+300>
```

## 2. create a file with correct header and data

```python
import struct

with open("flag.cimg", "wb") as f:
    magic = b"\x63\x49\x4d\x47"
    version = 1
    version = version.to_bytes(8, "little") # 0xc - 0x4 = 8 bytes
    width = b"\x42\x00" # compw instruction = 2 bytes
    height = b"\x11\x00"

    data = bytes([95 for _ in range(62*23)])

    f.write(magic)
    f.write(version)
    f.write(width)
    f.write(height)
    f.write(data)
```

## 3. run binary

```
hacker@reverse-engineering~input-restrictions-x86:/challenge$ ./cimg ~/flag.cimg
pwn.college{kVIT3Q_nTzEXgqNnBrvu4cZrRlr.0FNwMDMxwCM0YjMyEzW}
```
