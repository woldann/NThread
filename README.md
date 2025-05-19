# NThread

**NThread** is a powerful, x64-focused thread manipulation library designed to safely call functions inside target processes by leveraging their existing threads.

> ⚙️ Built for stealth, flexibility, and reliability — no injections, no hooks, just pure thread register control.

---

## ✨ Features

- ✅ **x64 Architecture Focused** — Designed specifically for x64 systems, currently supporting Windows x64.
- 🛡️ **Stealthy Operation** — Avoids common AV/EDR triggers by using no remote memory allocation or shellcode.
- 🔄 **Reversible Hijacking** — Temporarily controls target threads and restores them perfectly after use.
- 🔗 **Thread-Local Storage (TLS) or Equivalent** — Maps your control threads safely to target threads for smooth multi-thread management.
- ⚙️ **Flexible & Reliable** — Uses standard libc functions within the target process and supports advanced code reuse techniques.

---

## 🚫 Code Injection? Not Needed.

NThread does **not** rely on traditional code injection (e.g. shellcode, `VirtualAllocEx`, `CreateRemoteThread`, etc.).  
Instead, it uses pre-existing threads and simple instruction sequences already present in most executables.

If the target process already contains the following instruction pattern:

```assembly
0x7f0000 0x55          push rbp
0x7f0001 0xC3          ret

0x7f0050 0xEB 0xFE     jmp $
```

You can locate such an address and use it directly with `ntu_init`:
```c
ntu_init(tid, existing_push_addr=0x7f0000, existing_jmp_addr=0x7f0050);
```

Alternatively, as demonstrated in [tests/inject.c](https://github.com/woldann/NThread/blob/main/tests/inject.c) you can allocate this code into the target process yourself:
```c
int8_t push_sleep[] = { 0x55, 0xC3, 0xEB, 0xFE };

// Allocate memory in target process and write code
void *push_sleep_addr = VirtualAllocEx(...);
WriteProcessMemory(..., push_sleep_addr, push_sleep, sizeof(push_sleep));

// Initialize NThread with known valid instructions
ntu_init(tid, push_sleep_addr, push_sleep_addr + 2);
```

---

## ⚙️ Supported Platforms

- Windows x64 (currently only)
