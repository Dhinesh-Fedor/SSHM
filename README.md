# SSHM Toolkit — Secure Shared Memory Toolkit (v1.0)

This repository contains a minimal but complete implementation of SSHM Toolkit:
secure shared memory IPC with optional encryption (libsodium), double-buffering,
and per-segment named semaphores.

**Version:** 1.0

## Build

Requires: libsodium, pthreads, POSIX shm support.

```bash
make
```

This produces:
- libsshm.a
- libsshm.so
- sshmctl (CLI)

## Quick usage

Generate a key (32 bytes) using the example or `sshm_generate_key` in code.
Create a segment:
```bash
./sshmctl create myseg 4096 --enc ./key.bin
```

Write:
```bash
./sshmctl write myseg message.bin
```

Read:
```bash
./sshmctl read myseg out.bin
```

## Notes

This implementation is meant as a production-grade starting point but intentionally
keeps some parts (WAL, audit HMAC) simplified for clarity. Before shipping,
add more robust CRC, WAL replay, and audit signing.

