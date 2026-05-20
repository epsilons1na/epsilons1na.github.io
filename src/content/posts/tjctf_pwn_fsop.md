---
title: "[TJ-CTF 2026]-Pwn/Ox78"
published: 2026-05-19
description: "Easy fsop~"
tags: ["pwn", "heap","fsop",]
category: userland

---
### Overview
This weekend, I played tjctf after a long time and solved this fsop challenge.The challenge is simple, author tried to prevent fsop by nulling the ```_chain``` of file structure but it quite did not work.
The binary leaks the heap address and libc address thus we can bypass ASLR without any headache.
Although heap leak is not necessay in this challenge but some players solved it using both leaks.
```md
./ld-linux-x86-64.so.2 ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.34-0ubuntu3) stable release version 2.34.
Copyright (C) 2021 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 10.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```
```md
Basic information
Canary                                  : Disabled
NX                                      : Enabled
PIE                                     : Enabled
RELRO                                   : Full RELRO
Fortify                                 : Not found

```
### Source code
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  Ox78();
  return 0;
}
```
This is the main function. It does some religious buffering and then calls another function.
```c
__int64 Ox78()
{
  const void *v0; // rax

  create_test_file();
  testbuf = malloc(0x78uLL);
  fp = fopen("/tmp/test.txt", "r");
  puts(
    "I'm trying to test my FSOP prevention mechanism so I can share it with my coworkers who know nothing about security."
    " It should be foolproof right?\n");
  printf("Here's the address of the File Structure: 0x%llx\n", fp);
  v0 = (const void *)puts_got_value();
  printf("I'm pretty confident you can't break out of this, so I'll give you a libc leak as well: %p\n\n", v0);
  read(0, fp, 0x78uLL);
  prevent_fsop();
  fread(testbuf, 1uLL, 0x78uLL, fp);
  prevent_fsop();
  return 0LL;
}
```
Too many buzz loc!
```c
read(0, fp, 0x78uLL);
prevent_fsop();->nulls the _chain;
fread(testbuf, 1uLL, 0x78uLL, fp);

```
This is the real thing. It grants write primitive on file structure(fp) and then use this fp to read in testbuf.

```md
# gef> ptype/ox FILE*
# type = struct _IO_FILE {
# /* 0x0000      |  0x0004 */    int _flags;
# /* XXX  4-byte hole      */
# /* 0x0008      |  0x0008 */    char *_IO_read_ptr;
# /* 0x0010      |  0x0008 */    char *_IO_read_end;
# /* 0x0018      |  0x0008 */    char *_IO_read_base;
# /* 0x0020      |  0x0008 */    char *_IO_write_base;
# /* 0x0028      |  0x0008 */    char *_IO_write_ptr;
# /* 0x0030      |  0x0008 */    char *_IO_write_end;
# /* 0x0038      |  0x0008 */    char *_IO_buf_base;
# /* 0x0040      |  0x0008 */    char *_IO_buf_end;
# /* 0x0048      |  0x0008 */    char *_IO_save_base;
# /* 0x0050      |  0x0008 */    char *_IO_backup_base;
# /* 0x0058      |  0x0008 */    char *_IO_save_end;
# /* 0x0060      |  0x0008 */    struct _IO_marker *_markers;
# /* 0x0068      |  0x0008 */    struct _IO_FILE *_chain;
# /* 0x0070      |  0x0004 */    int _fileno;
# /* 0x0074      |  0x0004 */    int _flags2;
# /* 0x0078      |  0x0008 */    __off_t _old_offset;
```
with this write primitive we control many of the pointers of fp and this can be used to gain arbitrary write primitve. And we have libc leak thus making it very easy to write anywhere in libc and  get shell.

```c
size_t
_IO_fread (void *buf, size_t size, size_t count, FILE *fp)
{
  size_t bytes_requested = size * count;
  size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
```
This is implementation of fread in libc.I have pasted all the source code below and will explain the path which will lead to arb write.Above code calculates bytes_requested then sanity check the file structure(fp->this is the same fp that we have write primitive on.), then does some locking stuff and calls _IO_sgetn.

```c

size_t
_IO_sgetn (FILE *fp, void *data, size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n);
}
libc_hidden_def (_IO_sgetn)
--------------------------------------------------------------------------------
#define _IO_XSGETN(FP, DATA, N) JUMP2 (__xsgetn, FP, DATA, N)
JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
```
_IO_sgetn is just a call to _IO_XSGETN which is a jump to a pointer in vtable. I don't understand this correctly but seeing it in gef, I found the call to _IO_file_xsgetn.

```asm
0x7e996ea91f60 <__GI__IO_sgetn> (
   FILE* fp = 0x000057d173e45320  ->  0x0000000000000800,->fp
   void* data = 0x000057d173e452a0  ->  0x0000000000000000,->test_buffer
   size_t n = 0x0000000000000078,->length
)
```
This is the heap structure for better understanding!
```md
0x57d173e45000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000291 |
0x57d173e45010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000000 |
* 39 lines, 0x270 bytes
--test buffer-----------------------------------------------------------
0x57d173e45290|+0x00000|+0x00290: 0x0000000000000000 0x0000000000000081 |  |
0x57d173e452a0|+0x00010|+0x002a0: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e452b0|+0x00020|+0x002b0: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e452c0|+0x00030|+0x002c0: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e452d0|+0x00040|+0x002d0: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e452e0|+0x00050|+0x002e0: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e452f0|+0x00060|+0x002f0: 0x0000000000000000 0x0000000000000000 |
0x57d173e45300|+0x00070|+0x00300: 0x0000000000000000 0x0000000000000000 |
-------------------------------------------------------------------------
0x57d173e45310|+0x00000|+0x00310: 0x0000000000000000 0x00000000000001e1 |
--starting of file structure(fp)----------------------------------------
0x57d173e45320|+0x00010|+0x00320: 0x0000000000000800 0x0000000000000000 |
0x57d173e45330|+0x00020|+0x00330: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e45340|+0x00030|+0x00340: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e45350|+0x00040|+0x00350: 0x0000000000000000 0x00007e996ec19660 |
0x57d173e45360|+0x00050|+0x00360: 0x00007e996ec19780 0x0000000000000000 |
0x57d173e45370|+0x00060|+0x00370: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e45380|+0x00070|+0x00380: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e45390|+0x00080|+0x00390: 0x0000000000000000 0x0000000000000000 |  |
0x57d173e453a0|+0x00090|+0x003a0: 0x0000000000000000 0x000057d173e45400 |
0x57d173e453b0|+0x000a0|+0x003b0: 0xffffffffffffffff 0x0000000000000000 |  |
0x57d173e453c0|+0x000b0|+0x003c0: 0x000057d173e45410 0x0000000000000000 |
0x57d173e453d0|+0x000c0|+0x003d0: 0x0000000000000000 0x0000000000000000 |
0x57d173e453e0|+0x000d0|+0x003e0: 0x0000000000000000 0x0000000000000000 |
0x57d173e453f0|+0x000e0|+0x003f0: 0x0000000000000000 0x00007e996ec1a560 |
0x57d173e45400|+0x000f0|+0x00400: 0x0000000100000001 0x00007e996ec92740 |
0x57d173e45410|+0x00100|+0x00410: 0x0000000000000000 0x0000000000000000 |
* 13 lines, 0xd0 bytes
0x57d173e454f0|+0x00000|+0x004f0: 0x00007e996ec1a020 0x0000000000020b11 |
(this is the memory strcuture a/ exploit script->change it with ASLR OFF)
```
```asm
 -> 0x7e996ea83c34 e827e30000            <fread+0x74>   call   0x7e996ea91f60 <__GI__IO_sgetn>

   -> 0x7e996ea91f60 f30f1efa              <_IO_sgetn>   endbr64
      0x7e996ea91f64 53                    <_IO_sgetn+0x4>   push   rbx
      0x7e996ea91f65 488d0df4791800        <_IO_sgetn+0x5>   lea    rcx, [rip + 0x1879f4] # 0x7e996ec19960 <_IO_helper_jumps>
      0x7e996ea91f6c 488d0555871800        <_IO_sgetn+0xc>   lea    rax, [rip + 0x188755] # 0x7e996ec1a6c8 <__elf_set___libc_atexit_element__IO_cleanup__>
      0x7e996ea91f73 4829c8                <_IO_sgetn+0x13>   sub    rax, rcx
      0x7e996ea91f76 4883ec20              <_IO_sgetn+0x16>   sub    rsp, 0x20

```
Below is the implementation of _IO_file_xsgetn.


```c
size_t
_IO_file_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t want, have;
  ssize_t count;
  char *s = data;

  want = n;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }
```
We don't want to go into this path so fp->_IO_buf_base == NULL this condition should be false.
```c
  while (want > 0)/*this condition is true*/
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (want <= have)/*we don' want this condition */
	{
	  memcpy (s, fp->_IO_read_ptr, want);
	  fp->_IO_read_ptr += want;
	  want = 0;
	}
      else
	{
	  if (have > 0)/*again undesirable*/
	    {
	      s = __mempcpy (s, fp->_IO_read_ptr, have);
	      want -= have;
	      fp->_IO_read_ptr += have;
	    }

	  /* Check for backup and repeat */
	  if (_IO_in_backup (fp))/*test   DWORD PTR [rbx], 0x100*/
	    {/*what can i say except don't go into this !!*/
	      _IO_switch_to_main_get_area (fp);
	      continue;
	    }

	  /* If we now want less than a buffer, underflow and repeat
	     the copy.  Otherwise, _IO_SYSREAD directly to
	     the user buffer. */
	  if (fp->_IO_buf_base
	      && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
	    {/*desirable condition as this will call __underflow and so on......*/
	      if (__underflow (fp) == EOF)
		break;

	      continue;
	    }
}
/*skipped the rest loc */
libc_hidden_def (_IO_file_xsgetn)
```
Nothing interesting except __underflow. Touring the code below we can find the call to again a pointer in vtable which is _IO_UNDERFLOW.
```c

int
__underflow (FILE *fp)
{
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;//this condition is not in disassembly i don't know the reason.

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))/*#define _IO_in_put_mode(_fp) ((_fp)->_flags & _IO_CURRENTLY_PUTTING)*/
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  if (_IO_in_backup (fp))/*#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)*/
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end)
	return *(unsigned char *) fp->_IO_read_ptr;
    }
  if (_IO_have_markers (fp))/*#define _IO_have_markers(fp) ((fp)->_markers != NULL) */
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))/*#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)*/
    _IO_free_backup_area (fp);
  return _IO_UNDERFLOW (fp);
}
libc_hidden_def (__underflow)
```
Somehow we have to find a path that will successfully reach this return _IO_UNDERFLOW (fp).
Most of the above condition is just one loc defined as macro in libiop.h and is very easy to read.I don't wanna yoink everything cuz I am lazy...

```c

int
_IO_new_file_underflow (FILE *fp)
{
  ssize_t count;

  /* Nope */
  if (fp->_flags & _IO_EOF_SEEN)
    return EOF;
/*Again Nope */
  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }/*Nope */
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
    /*Nope */
  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }
  /*Hell naww */

  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (stdout);

      if ((stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (stdout, EOF);

      _IO_release_lock (stdout);
    }

  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
/*Gem Alert!!! */

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);
           /*do not care loc!!!!*/
  if (count <= 0)
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)

```
Now  this loc is banger cuz it calls read with all arguments in user control. A simple receipe to arbitrary write.
```c
---------------------------------------------------------------
count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);

----------------------------------------------------------------
#define _IO_SYSREAD(FP, DATA, LEN) JUMP2 (__read, FP, DATA, LEN)
__read (int fd, void *buf, size_t nbytes)
{
  return __pread64 (fd, buf, nbytes, -1);
}
libc_hidden_weak (__read)
```
This is most of the bits that will manipulate the path as most of the if conditions relies on the _flag of fp.
```c
/* Magic number and bits for the _flags field.  The magic number is
   mostly vestigial, but preserved for compatibility.  It occupies the
   high 16 bits of _flags; the low 16 bits are actual flag bits.  */

#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000

```
Listing all of the conditions-
- fp->_IO_buf_base -> start of the write address.
- fp->_IO_buf_end ->end of the write address.
- length = fp->_IO_buf_end - fp->_IO_buf_base and this should be greater than want which is 0x78.
- _flag & ~_IO_NO_WRITES
- _flag |= _IO_CURRENTLY_PUTTING

To explain how the flags will be used I will again copypasta source code(i am sowwwy).
//TODO:explain the flag


### Exploit
Context: After getting arbitrary write, I mindlessly went for house of apple 2 cuz why not? so I overwrote stderr with payload that I made long ago and waited for low cortisol shell,but what i recevied was high cortisol EOF.

I am not explaining house of apple 2. there are tons of blogs on internet and that explains better!
well EOF is not shell so I started debugging exit handler in gdb and reached at this code.

```c

int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```
My payload relied on the fact that _IO_OVERFLOW (fp, EOF) this should be called with fp as stderr which should be easy peasy cuz
_IO_list_all is linked list that points to stderr. and then next fp traverses via _chain.But guess what i did not account for ,the new file structure which was allocated on heap.May be I did but I think, I assumed it to be placed at the end of linked list which was not the case.
and the reason is this
```c

void
_IO_link_in (struct _IO_FILE_plus *fp)
{
  if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
#ifdef _IO_MTSAFE_IO/*hmm cool but not relevant to this chall*/
      _IO_cleanup_region_start_noarg (flush_cleanup);
      _IO_lock_lock (list_all_lock);
      run_fp = (FILE *) fp;
      _IO_flockfile ((FILE *) fp);
#endif
      fp->file._chain = (FILE *) _IO_list_all;
      _IO_list_all = fp;
#ifdef _IO_MTSAFE_IO
      _IO_funlockfile ((FILE *) fp);
      run_fp = NULL;
      _IO_lock_unlock (list_all_lock);
      _IO_cleanup_region_end (0);
#endif
    }
}
libc_hidden_def (_IO_link_in)
```
fopen internally calls this function _IO_link_in and fp is inserted at the head of the linked list so now __GI__IO_list_all is like fp->stderr->stdout->stdin->0x0 and before exiting prevent_fsop nulls the _chain which breaks the linked list to only fp->0x0 and thus EOF.
```asm
 -> 0x79b097e9137a 488b15df821800        <_IO_link_in+0xfa>   mov    rdx, QWORD PTR [rip + 0x1882df] # 0x79b098019660 <__GI__IO_list_all>
    0x79b097e91381 83470401              <_IO_link_in+0x101>   add    DWORD PTR [rdi + 0x4], 0x1
    0x79b097e91385 48896f08              <_IO_link_in+0x105>   mov    QWORD PTR [rdi + 0x8], rbp
    0x79b097e91389 48891dd0821800        <_IO_link_in+0x109>   mov    QWORD PTR [rip + 0x1882d0], rbx # 0x79b098019660 <__GI__IO_list_all>
    0x79b097e91390 48895368              <_IO_link_in+0x110>   mov    QWORD PTR [rbx + 0x68], rdx

```
After debugging in gef, I found that __GI__IO_list_all is very close to _IO_2_1_stderr.
```asm
0x79b098019660 <__GI__IO_list_all>:	0x0000633a85c90320	0x0000000000000000
0x79b098019670:	                    0x0000000000000000	0x0000000000000000
0x79b098019680 <_IO_2_1_stderr_>:	  0x00000000fbad2086	0x0000000000000000
0x79b098019690 <_IO_2_1_stderr_+16>:0x0000000000000000	0x0000000000000000
0x79b0980196a0 <_IO_2_1_stderr_+32>:0x0000000000000000	0x0000000000000000
```
And with arb write primitive and libc leak, I just overwrote list_all to stderr thus calling _IO_OVERFLOW with fp as stderr
and profit!!

### A better exploit?
As libc version is 2.34, tls sections is alligned with libc sections and thus we can also overwrite dtor_list struct and get shell.I am too lazy to make exploit with this but I will just yoink the src code and disassembly and explain some stuff.
```c
typedef void (*dtor_func) (void *);

struct dtor_list
{
  dtor_func func;
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};

void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif

      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);

      /* Ensure that the MAP dereference happens before
	 l_tls_dtor_count decrement.  That way, we protect this access from a
	 potential DSO unload in _dl_close_worker, which happens when
	 l_tls_dtor_count is 0.  See CONCURRENCY NOTES for more detail.  */
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
libc_hidden_def (__call_tls_dtors)
```

```asm
Dump of assembler code for function __GI___call_tls_dtors:
   0x0000777d6fe49dc0 <+0>:	endbr64
   0x0000777d6fe49dc4 <+4>:	push   rbp
   0x0000777d6fe49dc5 <+5>:	push   rbx
   0x0000777d6fe49dc6 <+6>:	sub    rsp,0x8
   0x0000777d6fe49dca <+10>:	mov    rbx,QWORD PTR [rip+0x1cdfbf]        # 0x777d70017d90
   0x0000777d6fe49dd1 <+17>:	mov    rbp,QWORD PTR fs:[rbx]
   0x0000777d6fe49dd5 <+21>:	test   rbp,rbp
   0x0000777d6fe49dd8 <+24>:	je     0x777d6fe49e1d <__GI___call_tls_dtors+93>
   0x0000777d6fe49dda <+26>:	nop    WORD PTR [rax+rax*1+0x0]
   0x0000777d6fe49de0 <+32>:	mov    rdx,QWORD PTR [rbp+0x18]
   0x0000777d6fe49de4 <+36>:	mov    rax,QWORD PTR [rbp+0x0]
   0x0000777d6fe49de8 <+40>:	ror    rax,0x11
   0x0000777d6fe49dec <+44>:	xor    rax,QWORD PTR fs:0x30
   0x0000777d6fe49df5 <+53>:	mov    QWORD PTR fs:[rbx],rdx
   0x0000777d6fe49df9 <+57>:	mov    rdi,QWORD PTR [rbp+0x8]
   0x0000777d6fe49dfd <+61>:	call   rax
   0x0000777d6fe49dff <+63>:	mov    rax,QWORD PTR [rbp+0x10]
   0x0000777d6fe49e03 <+67>:	lock sub QWORD PTR [rax+0x468],0x1
   0x0000777d6fe49e0c <+76>:	mov    rdi,rbp
   0x0000777d6fe49e0f <+79>:	call   0x777d6fe2c350 <free@plt>
   0x0000777d6fe49e14 <+84>:	mov    rbp,QWORD PTR fs:[rbx]
   0x0000777d6fe49e18 <+88>:	test   rbp,rbp
   0x0000777d6fe49e1b <+91>:	jne    0x777d6fe49de0 <__GI___call_tls_dtors+32>
   0x0000777d6fe49e1d <+93>:	add    rsp,0x8
   0x0000777d6fe49e21 <+97>:	pop    rbx
   0x0000777d6fe49e22 <+98>:	pop    rbp
   0x0000777d6fe49e23 <+99>:	ret
```
while loop check is at +24,  and rbx contains negative value fs:rbx is the address of struct dtor_list.We have to null the fs:0x30(random_value) cuz then at +44 xor operation will have no effect. So overwriting func with with system<<17 and then obj with address of "bin/sh" will give the shell.


### Aftermath

Nice challenge! Touring libc source code is fun.


### References
https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc
https://elixir.bootlin.com/glibc/glibc-2.34/source/stdlib/cxa_thread_atexit_impl.c#L89
https://elixir.bootlin.com/glibc/glibc-2.34/source/libio/genops.c#L86
https://elixir.bootlin.com/glibc/glibc-2.34/source/libio/genops.c#L685
