# Secure File Server - Pwn Task Writeup

This is my writeup for the binary exploitation challenge called **Secure File Server**.

Binary Information:

```
$ file main
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, BuildID[sha1]=332399459481264b892195d46b87bb255968c8ff, not stripped
```

Security Protections:

```
$ pwn checksec main
[*] '/home/dexter/Desktop/SecureFileServer/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```

Summary:

- PIE (Position Independent Executable) and NX (Non-Executable Stack) are enabled.
- Full RELRO (Read-Only Relocations) is enabled.
- No stack canary is present, which may allow stack-based buffer overflow attacks.
- The binary is not stripped, so symbols are available to assist in reversing.
- RUNPATH is set to the current directory (`.`), which could affect dynamic linking behavior.

Exploitation Strategy:

This section should include your analysis of the binary, the vulnerabilities you identified, and a detailed explanation of how you developed the exploit. Include information such as how you bypassed protections, leaked addresses if needed, constructed your payload, and achieved code execution.
