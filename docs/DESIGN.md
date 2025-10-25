# DESIGN — SSHM Toolkit (v1.0)

See top-level README. Key points:
- POSIX shm + mmap
- Named semaphores for synchronization
- Double-buffering to avoid partial reads from writers
- Optional AEAD encryption with libsodium (XChaCha20-Poly1305)
- Per-segment header stores flags, version, payload_size, crc32

Security:
- Keys are expected to be 32 bytes (application responsibility to store securely)
- Library zeros temporary buffers where possible

Fault tolerance:
- Double-buffering avoids torn writes
- Header versioning and CRC detect corruption
- WAL & advanced recovery omitted in this minimal implementation; recommended to add on top

