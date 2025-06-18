# Secure File Server - Writeup

---

## Exploit Demo

This demo illustrates the exploit process:

![Alt text](gif/SecureFileServer.gif)

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
- **No stack canary**

![Alt text](img/2.png)

---

## Static Analysis (IDA Pro / Ghidra)

Upon reversing, key functions were discovered to be vulnerable. Notably, the lack of stack canary allows for possible stack-based buffer overflows. Since symbols are available, reversing is easier.

Key functions and vulnerabilities are documented in the images below:

![Alt text](img/3.png)

---

## How to Solve

The binary likely contains a buffer overflow vulnerability due to the lack of a stack canary. PIE is enabled, so leaking addresses is necessary to calculate the base. With NX enabled, a ROP chain is a probable attack vector. The available symbols and local loading (`RUNPATH = '.'`) may also be leveraged for exploitation.

---

## Vulnerability Summary

- No stack canary → stack overflow possible.
- PIE → need to leak a code address for base calculation.
- NX enabled → shellcode injection blocked, ROP required.
- Full RELRO → GOT overwrite is not an option.
- Not stripped → functions are labeled, aiding reverse engineering.

---

## Exploit Strategy

1. **Leak a PIE address**
   Find a format string or info leak to determine binary base.

2. **Identify overflow point**
   Locate buffer overflow using fuzzing or reversing.

3. **Construct ROP chain**
   Use ROPgadget or similar to craft payload and call `system("/bin/sh")` or similar.

4. **Trigger overflow**
   Send crafted payload to gain shell or reveal flag.

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('main', checksec=False)
context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def start():
    if args.GDB:
        return gdb.debug([exe.path], gdbscript='b *main\nc')
    else:
        return process(exe.path)

io = start()

# Example placeholder for payload logic
payload = b'A' * offset  # overflow
payload += rop_chain     # ROP payload (e.g., system("/bin/sh"))

io.sendline(payload)
io.interactive()
```

---

## Result

After successfully exploiting the overflow and executing the ROP chain, the binary executes our controlled payload, potentially revealing the flag or giving shell access.

---

## FLAG

The flag will be displayed in the output after successful execution.

```
RedPointer{example_flag_goes_here}
```

---

Let me know if you want to plug in real screenshots or want help generating the actual exploit!
