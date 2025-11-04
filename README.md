# Binary Exploitation Lab — README

**Repository:** solutions and analyses for a  lab on binary exploitation (M2 CyberSecurity, Ensimag).  
This project demonstrates how memory-corruption bugs can be found and exploited, and how modern mitigations (NX/DEP, ASLR) change exploitation strategies. Each exercise contains the vulnerable binary, analysis notes, exploit code and short explanations.

---

## Table of contents
- [Overview](#overview)  
- [Key concepts & skills](#key-concepts--skills)  
- [Exercise 1 — Classical stack buffer overflow](#exercise-1---classical-stack-buffer-overflow)  
  - [Vulnerability](#vulnerability)  
  - [Exploitation strategy & payload layout](#exploitation-strategy--payload-layout)  
  - [Shellcode (cat /etc/passwd) example](#shellcode-cat-etcpasswd-example)  
- [Exercise 2 — Return-Oriented Programming (ROP)](#exercise-2---return-oriented-programming-rop)  
  - [Vulnerability](#vulnerability-1)  
  - [ROP strategy & gadgets](#rop-strategy--gadgets)  
  - [ROP example: execve("/bin/sh") and cat /etc/passwd](#rop-example-execvesbinsh-and-cat-etcpasswd)  
- [How to run the exploits](#how-to-run-the-exploits)  
  - [Prerequisites](#prerequisites)  
  - [Disabling ASLR (optional for Exercise 1)](#disabling-aslr-optional-for-exercise-1)  
  - [Commands](#commands)  

---

## Overview
This repository walks through two representative exploitation patterns:

1. A *classical stack-based buffer overflow* where the binary has an executable stack. We inject shellcode into the stack and overwrite the saved return address to jump into our payload.  
2. A *ROP-based exploit* for a binary compiled with a non-executable stack (NX). Instead of injecting code, we build a ROP chain using existing instructions (gadgets) to perform `execve`.

Each exercise includes:
- the vulnerable binary,
- annotated static analysis (Ghidra decompilation and notes),
- dynamic traces using GDB,
- the exploit source code (Python scripts that build payloads),
- optional extensions (e.g. `cat /etc/passwd` payload).

---

## Key concepts & skills
- **Static analysis:** reading decompiled output (Ghidra) to find unsafe library calls and control-flow structure.  
- **Dynamic analysis:** using GDB to inspect stack layout, registers, and memory at runtime.  
- **Buffer overflows:** understanding how overwriting saved frame data (saved RBP, return address) allows control-flow hijack.  
- **Shellcoding (x86-64):** writing small position-dependent assembly fragments that call `execve` or spawn a shell.  
- **ROP (Return-Oriented Programming):** chaining short instruction sequences (gadgets) already present in the binary to perform arbitrary syscalls despite NX.  
- **Linux ABI / internals:** x86-64 calling conventions (RDI, RSI, RDX, RAX), stack layout, system call numbers.

---

## Exercise 1 — Classical stack buffer overflow

### Vulnerability
The binary `Exercise1_Classical_BoF/bin/bof` calls `strcpy` to copy a user-supplied argument into a 256-byte local buffer without bounds checks:

```c
/* Decompiled vulnerable function (illustrative) */
void vuln(char *input) {
    char buffer[256];
    strcpy(buffer, input); /* unsafe: no length checks */
    printf("Something will happens ! %s\n", buffer);
}
# Binary Exploitation Lab — README

**Repository:** solutions and analyses for a university lab on binary exploitation (M2 CyberSecurity, Ensimag).  
This project demonstrates how memory-corruption bugs can be found and exploited, and how modern mitigations (NX/DEP, ASLR) change exploitation strategies. Each exercise contains the vulnerable binary, analysis notes, exploit code and short explanations.

---

## Table of contents
- [Overview](#overview)  
- [Key concepts & skills](#key-concepts--skills)  
- [Exercise 1 — Classical stack buffer overflow](#exercise-1---classical-stack-buffer-overflow)  
  - [Vulnerability](#vulnerability)  
  - [Exploitation strategy & payload layout](#exploitation-strategy--payload-layout)  
  - [Shellcode (cat /etc/passwd) example](#shellcode-cat-etcpasswd-example)  
- [Exercise 2 — Return-Oriented Programming (ROP)](#exercise-2---return-oriented-programming-rop)  
  - [Vulnerability](#vulnerability-1)  
  - [ROP strategy & gadgets](#rop-strategy--gadgets)  
  - [ROP example: execve("/bin/sh") and cat /etc/passwd](#rop-example-execvesbinsh-and-cat-etcpasswd)  
- [How to run the exploits](#how-to-run-the-exploits)  
  - [Prerequisites](#prerequisites)  
  - [Disabling ASLR (optional for Exercise 1)](#disabling-aslr-optional-for-exercise-1)  
  - [Commands](#commands)  

---

## Overview
This repository walks through two representative exploitation patterns:

1. A *classical stack-based buffer overflow* where the binary has an executable stack. We inject shellcode into the stack and overwrite the saved return address to jump into our payload.  
2. A *ROP-based exploit* for a binary compiled with a non-executable stack (NX). Instead of injecting code, we build a ROP chain using existing instructions (gadgets) to perform `execve`.

Each exercise includes:
- the vulnerable binary,
- annotated static analysis (Ghidra decompilation and notes),
- dynamic traces using GDB,
- the exploit source code (Python scripts that build payloads),
- optional extensions (e.g. `cat /etc/passwd` payload).

---

## Key concepts & skills
- **Static analysis:** reading decompiled output (Ghidra) to find unsafe library calls and control-flow structure.  
- **Dynamic analysis:** using GDB to inspect stack layout, registers, and memory at runtime.  
- **Buffer overflows:** understanding how overwriting saved frame data (saved RBP, return address) allows control-flow hijack.  
- **Shellcoding (x86-64):** writing small position-dependent assembly fragments that call `execve` or spawn a shell.  
- **ROP (Return-Oriented Programming):** chaining short instruction sequences (gadgets) already present in the binary to perform arbitrary syscalls despite NX.  
- **Linux ABI / internals:** x86-64 calling conventions (RDI, RSI, RDX, RAX), stack layout, system call numbers.

---

## Exercise 1 — Classical stack buffer overflow

### Vulnerability
The binary `Exercise1_Classical_BoF/bin/bof` calls `strcpy` to copy a user-supplied argument into a 256-byte local buffer without bounds checks:

```c
/* Decompiled vulnerable function (illustrative) */
void vuln(char *input) {
    char buffer[256];
    strcpy(buffer, input); /* unsafe: no length checks */
    printf("Something will happens ! %s\n", buffer);
}
