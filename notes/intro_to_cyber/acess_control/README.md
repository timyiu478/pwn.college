---
tags: ["Access Control", "Linux"]
title: "Access Control"
description: Access Control
reference: https://pwn.college/intro-to-cybersecurity/access-control/
---

# L1

> Flag owned by you with different permissions

The `/challenge/run` program will help to change the `/flag` file user owner from `root` to `hacker`

--- 

# L2

> Flag owned by you with different permissions

The `/challenge/run` program will help to change the `/flag` file group owner from `root` to `hacker`

--- 

# L3

> Flag owned by you with different permissions

```bash
hacker@access-control~level3:/challenge$ chmod 400 /flag
hacker@access-control~level3:/challenge$ cat /fag
```

--- 

# L4

> How does SETUID work?


`/bin/cat` process will run as `root` instead of `hacker` because of `SETUID`.

```
Before:
-rwxr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat
After:
-rwsr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat
hacker@access-control~level4:/challenge$ /bin/cat /flag
```

---

# L5

> How does SETUID and cp work?

The `/bin/cp` can open and read the `/flag` and write to the file `~/flag` owned `hacker`.

```
-rwsr-xr-x 1 root root 153976 Sep  5  2019 /bin/cp
hacker@access-control~level5:/challenge$ touch ~/flag
hacker@access-control~level5:/challenge$ /bin/cp /flag ~/flag
hacker@access-control~level5:/challenge$ cat ~/flag
```

--- 

# L6

> Flag owned by a different group

```
----r----- 1 root group_skcujjxg 60 Jul 25 16:18 /flag
The password for group_skcujjxg is: wacauykv
hacker@access-control~level6:/challenge$ grep 'group_skcujjxg' /etc/group # check group members
group_skcujjxg:x:1001:
hacker@access-control~level6:/challenge$ groups hacker
hacker : hacker
hacker@access-control~level6:/challenge$ usermod -a -G group_skcujjxg hacker # add hacker in to group group_skcujjxg
hacker@access-control~level6:/challenge$ groups hacker
hacker : hacker group_skcujjxg
----r----- 1 root group_skcujjxg 60 Jul 25 16:18 /flag
hacker@access-control~level6:/challenge$ newgrp group_skcujjxg # change current shell main group to  group_skcujjxg
Password:
hacker@access-control~level6:/challenge$ cat /flag
```

--- 

# L7

> Flag owned by you with different permissions, multiple users

```
Before:
-r-------- 1 root root 60 Jul 25 16:34 /flag
Created user user_dswmellh with password khecrspc
After:
-------r-- 1 hacker root 60 Jul 25 16:34 /flag
hacker@access-control~level7:/challenge$ su user_dswmellh # login with new user user_dswmellh
Password:
user_dswmellh@access-control~level7:/challenge$ cat /flag
```

--- 

# L8

> Flag owned by other users

same as L7

--- 

# L9

> Flag owned by other users

```
Before:
-r-------- 1 root root 60 Jul 25 16:38 /flag
Created user user_rjzorkfx with password vylbkmvy
After:
----r----- 1 root user_rjzorkfx 60 Jul 25 16:38 /flag
hacker@access-control~level9:/challenge$ su user_rjzorkfx
Password:
user_rjzorkfx@access-control~level9:/challenge$ groups user_rjzorkfx
user_rjzorkfx : user_rjzorkfx
user_rjzorkfx@access-control~level9:/challenge$ cat /flag
```

---

# L10

> Flag owned by a group

```
Before:
-r-------- 1 root root 60 Jul 25 16:39 /flag
Created user user_spwgouut with password woefwsgq
Created user user_uxwmwnct with password psevrdte
Created user user_mktucxpq with password fabwvmrj
Created user user_fhhzmctm with password ldelfjac
Created user user_oyhjdntq with password rbuxkldo
Created user user_itjihgra with password xqwazqxy
Created user user_zkzqniof with password gwsnhady
Created user user_ogsdmyvo with password bfmwdinj
Created user user_djeijyix with password nwtorjoj
Created user user_ppwaftkh with password izvwqtex
After:
----r----- 1 root group_mxw 60 Jul 25 16:39 /flag
hacker@access-control~level10:/challenge$ grep 'group_mxw' /etc/group # <--- check group members of group_mxw
group_mxw:x:1001:user_ppwaftkh
hacker@access-control~level10:/challenge$ su user_ppwaftkh
Password:
user_ppwaftkh@access-control~level10:/challenge$ cat /flag
```

---

# L11

> Find the flag using multiple users

1. 

```
user_kfhadbba@access-control~level11:/challenge$ su user_ufjulzlg
user_ufjulzlg@access-control~level11:/challenge$ cd /tmp/
user_ufjulzlg@access-control~level11:/tmp$ cd tmpvbpfw70f/
user_ufjulzlg@access-control~level11:/tmp/tmpvbpfw70f$ ls -alt
total 4
dr-xr-x--x 1 root user_ufjulzlg 22 Jul 25 16:42 .
drwxrwxrwt 1 root root          32 Jul 25 16:42 ..
-r--r----- 1 root user_kfhadbba 60 Jul 25 16:42 tmp9wd6j9md
```

2.

```
user_ufjulzlg@access-control~level11:/tmp/tmpvbpfw70f$ su user_kfhadbba
user_kfhadbba@access-control~level11:/tmp/tmpvbpfw70f$ cat tmp9wd6j9md
```

---

# L12

> Find the flag using multiple users

same as L11

---

# L13

> One Mandatory Access Control question without categories

---

# L14

> Five Mandatory Access Control questions without categories

---

# L15

> One Mandatory Access Control question with categories

---

# L16

> Five Mandatory Access Control questions with categories

---

# L17

> Automate answering 20 Mandatory Access Control questions with categories in one second

---

# L18

> Automate answering 64 Mandatory Access Control questions with categories in one second

---

# L19

> Automate Answering 128 Mandatory Access Control questions with random levels and categories in one second
