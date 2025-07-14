---
tags: ["Reverse Engineering", "File Format", "Magic Number"]
title: "File Format: Magic Numbers in x86"
description: Reverse engineering by checking the python script
reference: https://pwn.college/intro-to-cybersecurity/reverse-engineering/
---

# Problem

Similar to the [file_format_magic_numbers_python.md](file_format_magic_numbers_python.md), but in x86.

# Solution

## 1. Get the printable strings from the x86 code

It uses the `strcmp` function, probably to compare the file format.

```
hacker@reverse-engineering~file-formats-magic-numbers-x86:/challenge$ strings cimg 
/lib64/ld-linux-x86-64.so.2
3)zp .?
libc.so.6
exit
puts
__stack_chk_fail
stdin
strlen
__errno_location
read
dup2
stdout
fputc
stderr
geteuid
open
fprintf
setvbuf
strcmp
strerror
__libc_start_main
write
GLIBC_2.4
GLIBC_2.2.5
__gmon_start__
[]A\A]A^A_
/flag
  ERROR: Failed to open the flag -- %s!
  Your effective user id is not 0!
  You must directly run the suid binary in order to have the correct permissions!
  ERROR: Failed to read the flag -- %s!
.cimg
ERROR: Invalid file extension!
ERROR: Failed to read header!
ERROR: Invalid magic number!
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
cimg.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
__errno_location@@GLIBC_2.2.5
stdout@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
write@@GLIBC_2.2.5
_edata
strlen@@GLIBC_2.2.5
__stack_chk_fail@@GLIBC_2.4
dup2@@GLIBC_2.2.5
geteuid@@GLIBC_2.2.5
fputc@@GLIBC_2.2.5
read@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
fprintf@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
_dl_relocate_static_pie
__bss_start
main
setvbuf@@GLIBC_2.2.5
open@@GLIBC_2.2.5
read_exact
exit@@GLIBC_2.2.5
__TMC_END__
disable_buffering
strerror@@GLIBC_2.2.5
stderr@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.data
.bss
.comment
hacker@reverse-engineering~file-formats-magic-numbers-x86:/challenge$ 
```

## 2. check the assembly code after the call of `read_exact`

There are 4 `cmp` instructions, they probably check the magic number of the file. And, the `movzbl` instructions are used to move the byte (from the input file) to the `eax` register for comparison.



```
  4015d5:       e8 63 fe ff ff          call   40143d <read_exact>
  4015da:       0f b6 45 e4             movzbl -0x1c(%rbp),%eax
  4015de:       3c 5b                   cmp    $0x5b,%al
  4015e0:       75 18                   jne    4015fa <main+0xfa>
  4015e2:       0f b6 45 e5             movzbl -0x1b(%rbp),%eax
  4015e6:       3c 4d                   cmp    $0x4d,%al
  4015e8:       75 10                   jne    4015fa <main+0xfa>
  4015ea:       0f b6 45 e6             movzbl -0x1a(%rbp),%eax
  4015ee:       3c 36                   cmp    $0x36,%al
  4015f0:       75 08                   jne    4015fa <main+0xfa>
  4015f2:       0f b6 45 e7             movzbl -0x19(%rbp),%eax
  4015f6:       3c 45                   cmp    $0x45,%al
  4015f8:       74 16                   je     401610 <main+0x110>
  4015fa:       48 8d 3d 34 0b 00 00    lea    0xb34(%rip),%rdi 
```

## 3. Get the magic number

```
(gdb) print/c 0x5b
$4 = 91 '['
(gdb) print/c 0x4d
$6 = 77 'M'
(gdb) print/c 0x36
$7 = 54 '6'
(gdb) print/c 0x45
$8 = 69 'E'
```

## 4. Run the binary with the file that contains the correct magic number

```
hacker@reverse-engineering~file-formats-magic-numbers-x86:/challenge$ ./cimg ~/flag.cimg 
pwn.college{o97iZFfglsbAqfrWBHKbvWbUSS0.0FMwMDMxwCM0YjMyEzW}
```
