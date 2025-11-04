# Binary Exploitation Lab — README

Repository containing solutions and analyses for a small lab on binary exploitation (M2 CyberSecurity). The project demonstrates classic stack buffer overflow and return-oriented programming (ROP) exploits, with analysis notes, gadgets, and exploit scripts.

---

## Table of contents
- [Overview](#overview)
- [Repository layout](#repository-layout)
- [Exercise 1 — Classical stack buffer overflow](#exercise-1---classical-stack-buffer-overflow)
  - [Vulnerability](#vulnerability)
  - [Exploitation strategy & payload layout](#exploitation-strategy--payload-layout)
  - [Shellcode example (cat /etc/passwd)](#shellcode-example-cat-etcpasswd)
- [Exercise 2 — Return-Oriented Programming (ROP)](#exercise-2---return-oriented-programming-rop)
  - [Vulnerability](#vulnerability-1)
  - [ROP strategy & gadgets](#rop-strategy--gadgets)
- [How to run the exploits](#how-to-run-the-exploits)
  - [Prerequisites](#prerequisites)
  - [Disable ASLR (optional for Exercise 1)](#disable-aslr-optional-for-exercise-1)
  - [Example commands](#example-commands)

---

## Overview

This repository walks through two representative exploitation patterns:

1. A classical stack-based buffer overflow where the target binary has an executable stack: we inject shellcode into the stack and overwrite the saved return address to jump into our payload.
2. A ROP-based exploit for a binary compiled with a non-executable stack (NX): instead of injecting code we build a ROP chain from existing gadgets to perform an `execve` syscall.

Each exercise includes the vulnerable binary, analysis notes, gadget listings and exploit scripts.

## Repository layout

- `bin/bof` — vulnerable binary for the classical buffer overflow exercise
- `bin/rop` — vulnerable binary for the ROP exercise
- `exploit/` — helper scripts (payload builders, ROP helpers)
- `shellcode/` — assembly shellcode sources and tests
- `gadgets-rop.txt` — gadget listing useful for building ROP chains
- `TP-BOF-ROP-CySec.pdf` — lab instructions and background material

---

## Exercise 1 — Classical stack buffer overflow

### Vulnerability

The `bof` binary copies user-controlled input into a fixed-size stack buffer without proper bounds checks. In a typical decompiled form the vulnerable function looks like:

```c
/* illustrative decompilation */
void vuln(char *input) {
    char buffer[256];
    strcpy(buffer, input); /* unsafe: no length checks */
    printf("Something will happen! %s\n", buffer);
}
```

Because `strcpy` does not check the input length, providing a sufficiently long string overwrites saved frame data (saved RBP and the return address) allowing control-flow hijacking.

### Exploitation strategy & payload layout

Typical exploitation steps:
- Determine the offset to the saved return address (example: 256 bytes buffer + 8 saved RBP = 264 bytes).
- Find or leak the address of the stack buffer (with GDB or a primitive info leak).
- Construct a payload such as:

```
[ NOP sled ] + [ shellcode ] + [ padding up to saved return addr ] + [ return address -> into NOP sled ]
```

When the function returns, execution jumps into the NOP sled and slides into the injected shellcode.

### Shellcode example (cat /etc/passwd)

A small, null-free x86-64 shellcode can be used to execute `execve("/bin/cat", ["/bin/cat","/etc/passwd",NULL], NULL)`. See the `shellcode/` directory and `sh_catpsswd-ex1.py` for example assembly and helper code to build the payload.

---

## Exercise 2 — Return-Oriented Programming (ROP)

### Vulnerability

The `rop` binary reads more bytes than a smaller stack buffer can hold (for example using `fgets`/`gets` variants), creating a buffer overflow while the stack is non-executable (NX enabled). Instead of injecting code, the exploit builds a ROP chain using gadgets already present in the program or linked libraries.

### ROP strategy & gadgets

High-level steps for a typical ROP-based `execve("/bin/sh", NULL, NULL)` exploit:

1. Write the string `/bin/sh` into a writable memory section (e.g. `.data`) using a write-what-where gadget such as `mov qword ptr [rdx], rax; ret`.
2. Use `pop rdi; ret` to set `RDI` to the address of `/bin/sh`.
3. Use `pop rsi; ret` and `pop rdx; ret` to set `RSI` and `RDX` to 0 (NULL).
4. Use `pop rax; ret` to set `RAX` to the syscall number for `execve` (59 on x86-64).
5. Call a `syscall; ret` gadget to make the system call and spawn a shell.

More complex payloads (e.g. `cat /etc/passwd`) require writing multiple strings and constructing an `argv` array in memory before invoking `execve`.

The file `gadgets-rop.txt` contains gadget addresses and listing that help build the chain.

---

## How to run the exploits

### Prerequisites
- Linux x86-64
- Python 3
- GDB (for debugging)
- Ensure the provided binaries are executable: `chmod +x bin/*`

### Disable ASLR (optional for Exercise 1)

When testing the classical buffer overflow outside of GDB, you may want to disable ASLR for reproducible stack addresses:

```bash
sudo sysctl -w kernel.randomize_va_space=0
```

Remember to re-enable ASLR after testing:

```bash
sudo sysctl -w kernel.randomize_va_space=2
```

### Example commands

- Test classical buffer overflow (shellcode / cat payload):

```bash
python3 sh_catpsswd.py | ./bin/bof
```

- Test ROP payload builder and run against the `rop` binary (keeps stdin open with `cat` so interactive shells survive):

```bash
(python3 exploit/sh_catpsswd_ex2.py; cat) | ./bin/rop
```

Inspect the exploit scripts in `exploit/` and `sh_catpsswd_ex2.py` to see how payloads are constructed and adjust addresses/gadgets for your environment.

For more details, analysis traces and annotated decompilations, see `TP-BOF-ROP-CySec.pdf` and the `gadgets-rop.txt` file.
