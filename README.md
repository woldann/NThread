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

## ⚙️ Supported Platforms

- Windows x64 (currently only)

