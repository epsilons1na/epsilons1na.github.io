---
title: "C++-Notes"
published: 2026-02-12
description: "Some cool stuff that I learned!! "
tags: ["std","cpp"]
category: Cpp/C
---

### Overview
This is summary of some stuff that I learned, mostly cpp pwn stuff and src code and how does std::some_shiii works? why cpp is so shii compared to c? and 
then maybe I will explore some stuff in rust if I get some time..
Mainly I started this cuz who knows? ~~I forgot why I started it..~~
Oh I remember it..

### Plan
I will explain what is cpp ?, then OOPS in cpp ? then structure of STL containers in cpp. and then some cpp pwn writeups.I can get enough content for this blog cuz of this blog from ptr-yudai.

So cpp is statically typed language, means all of its memory structure of variable  will be known to compile before runtime and will be laid accordingly in memory. 
TODO->later add some generic stuff

### Extras(Don't know where to put)
g++ (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0
Copyright (C) 2021 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
This is the compiler version I am mentioning here just for the sake of correctness as In laugh ctf, a challenge was compiled with 9.0 version  and that was vulnerable  to exception handling and some stuff idk


### OOPS
































### STL 
stl stands for standard template library. first of all why is it used?
stl consists of common template library that provides useful programming tools.
It includes ready-made classes and functions for handling common data structures and algorithms.
and containers are specific component within the STL, used to store data and manage data collections.like vector and string is a  container used to store  data.

### std::string

std::string provides a way to store sequence of characters in object variable for eg std::string some_var = "ABC".string can contain any types of data .

Currently due to noise in my background I am yoinking some stuff from this blog.
to see in memory view, how string is working, I am going to write some tuff code and then see in gef.
```c++
#include <iostream>
#include <stdio.h>

int main() {
  std::string var = "AAAA";
  std::cout << var << std::endl;
  return 0;
}```
and then after compiling with g++, we get as expected output
```md
./main 
AAAA
```
Also I have always been afraid of assembly of c++ cuz of scary constructor and destructor. So I am going to explain all the stuff I will encounter...
```asm
   0x0000000000002429 <+0>:	endbr64 
   0x000000000000242d <+4>:	push   rbp
   0x000000000000242e <+5>:	mov    rbp,rsp
   0x0000000000002431 <+8>:	push   rbx
   0x0000000000002432 <+9>:	sub    rsp,0x48
   0x0000000000002436 <+13>:	mov    rax,QWORD PTR fs:0x28
   0x000000000000243f <+22>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000000000002443 <+26>:	xor    eax,eax
   0x0000000000002445 <+28>:	lea    rax,[rbp-0x41]
   0x0000000000002449 <+32>:	mov    rdi,rax
   0x000000000000244c <+35>:	call   0x2310 <std::allocator<char>::allocator()
 ```
This part of asm just prepares  stack and then takes the canary value from fs:0x28, to stack and then store load stack address to rdi and calls the 
std::allocator.Now I don't know std::allocator..
If we see the cpp reference of std::allocator.
stepping in allocator assembly..




























```asm
   0x0000555555556451 <+40>:	lea    rdx,[rbp-0x41]
   0x0000555555556455 <+44>:	lea    rax,[rbp-0x40]
   0x0000555555556459 <+48>:	lea    rcx,[rip+0xba8]        # 0x555555557008
   0x0000555555556460 <+55>:	mov    rsi,rcx
   0x0000555555556463 <+58>:	mov    rdi,rax
   0x0000555555556466 <+61>:	call   0x55555555666a <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string<std::allocator<char> >(char const*, std::allocator<char> const&)>
```
this part of asm load [rbp-0x41] address to rdx , [rbp-0x40] to rax and some value form .rodata, then calls some scary stuff...
```asm
   0x000055555555646b <+66>:	lea    rax,[rbp-0x41]
   0x000055555555646f <+70>:	mov    rdi,rax
   0x0000555555556472 <+73>:	call   0x555555556280 <std::allocator<char>::~allocator()@plt>
```asm
then it calls destructor for allocator, means object which is in "rdi" is destroyed.
I think I am forgetting constructor and destructor..
so I am going to revise it
The main purpose of constructor to initialize the cpp objects,here  allocator is called I am assuming It initialized  some memory section which std::string will use and then after work is done it is destroyed returning the address for variable name "var".

I am going to verify this...
```asm
   0x00005555555564d6 <+173>:	mov    rax,rbx
   0x00005555555564d9 <+176>:	mov    rdi,rax
   0x00005555555564dc <+179>:	call   0x555555556300 <_Unwind_Resume@plt>
   0x00005555555564e1 <+184>:	endbr64 
   0x00005555555564e5 <+188>:	mov    rbx,rax
   0x00005555555564e8 <+191>:	lea    rax,[rbp-0x40]
   0x00005555555564ec <+195>:	mov    rdi,rax
   0x00005555555564ef <+198>:	call   0x5555555561f0 <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()@plt>
   0x00005555555564f4 <+203>:	mov    rax,rbx
   0x00005555555564f7 <+206>:	mov    rdi,rax
   0x00005555555564fa <+209>:	call   0x555555556300 <_Unwind_Resume@plt>
   0x00005555555564ff <+214>:	call   0x5555555562b0 <__stack_chk_fail@plt>
   0x0000555555556504 <+219>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x0000555555556508 <+223>:	leave  
   0x0000555555556509 <+224>:	ret    
```
This is the last part and calls some unwinding stuff.. 
I am going to explain all the stuff in writeups section...


### Vector 

found some intersting stuff but from the perspective of vector so gonna speedrun it..

the main reason to call std::allocator is to manage memory for any stl library that is going to be called like std::string which is called here.







