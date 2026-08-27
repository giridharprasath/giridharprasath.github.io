---
layout: post
title: "rop-write"
date: 2020-05-06
tags: ["2020", "pwn", "ctf"]
summary: "z3hro ctf pwn writeup"
---

# c4n4ry(1000pts)

This pwn challenge is from zh3r0 CTF which had a good set of problems for beginners.

```diff
-Arch:     amd64-64-little
-RELRO:    Partial RELRO
-Stack:    No canary found
-NX:       NX enabled
-PIE:      No PIE (0x400000)
```
No ASLR or PIE only NX is enabled.

# Binary analysis

The bug is at `vuln` function. There is a custom canary set in bss section. `vuln` compares the custom canary `key` with our input. `key` is only 4bytes. Bruteforce is the only option. There were hints that said `key` is an ordered-lower-case string which made it even easier, there is a `gets` which leads to a vanilla stack bof and with no canary we can start our exploitation.

# Exploit

`key` is present 192 bytes from the `gets` buffer. rbp is 12 bytes after `key`. we get control of ret address

## Gadgets

```diff
+0x0000000000400927 : mov qword ptr [r11], r12 ; ret
+0x0000000000400933 : pop r11 ; ret
+0x0000000000400936 : pop r12 ; ret
+0x0000000000400939 : pop rdi ; ret
```

There is a writeable page of 2000 bytes in the binary at `0x602000-0x603000`. So we gonna write "//bin/sh" in some memory and pop some gadgets.

# Final exploit

`JUNK + CANARY + JUNK + POP_R12_RET + BIN_SH + POP_R11_RET + WRITE + POP_RDI + WRITE + SYSTEM_ADDR`

## Full exploit and binary
[c4n4ry](https://github.com/GiridharPrasath/ctf/tree/master/pwn)
