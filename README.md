# My Cybersecurity Lab Portfolio

Welcome to my portfolio of hands-on cybersecurity labs, completed as part of my M2 CyberSecurity program. This repository serves as a collection of my practical work in vulnerability analysis and binary exploitation, demonstrating my ability to move from theoretical knowledge to real-world application.

Each directory in this repository represents a self-contained lab focused on a specific class of software vulnerability or exploitation technique.

## Purpose of This Portfolio

The primary goal of these labs is to develop a deep, practical understanding of how software vulnerabilities arise and how they can be exploited. This involves:

*   **Systematic Analysis:** Learning to dissect unknown binaries to find security flaws.
*   **Creative Problem-Solving:** Developing custom exploits to bypass security mitigations.
*   **Mastery of Tools:** Gaining proficiency with industry-standard tools for debugging, reverse engineering, and exploit development.

This collection showcases my hands-on skills in offensive security, my understanding of low-level system architecture, and my commitment to continuous learning in the field of cybersecurity.

---

## Core Concepts and Skills Developed

Across these labs, I have developed and demonstrated proficiency in the following areas:

#### Vulnerability Analysis & Reverse Engineering
*   **Static Analysis:** Decompiling and analyzing binary code using tools like **Ghidra** to understand program logic and identify potential vulnerabilities.
*   **Dynamic Analysis:** Using debuggers like **GDB** with extensions (PEDA/GEF) to inspect program state, control execution flow, and analyze memory at runtime.

#### Exploitation Techniques
*   **Stack-Based Buffer Overflows:** Hijacking program control by overwriting the return address on the stack.
*   **Shellcoding:** Writing and injecting custom x86-64 assembly code to achieve arbitrary code execution.
*   **Return-Oriented Programming (ROP):** Bypassing Data Execution Prevention (DEP/NX) by chaining existing code snippets ("gadgets") to perform complex operations.
*   **Bypassing Mitigations:** Developing strategies to defeat security mechanisms like ASLR (Address Space Layout Randomization) and Stack Canaries.


#### Essential Tooling
*   **Programming:** Using **Python** (often with the `pwntools` library) for rapid exploit development and automation.
*   **Assembly:** Reading and writing low-level **x86-64 Assembly** for shellcode and understanding gadget behavior.
*   **Linux Environment:** Working extensively in a Linux environment and leveraging command-line tools for analysis and scripting.

---
